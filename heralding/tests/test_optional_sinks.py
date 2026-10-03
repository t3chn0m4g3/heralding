import asyncio
import json
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from heralding.misc import privileges
from heralding.reporting.curiosum_sink import CuriosumSink
from heralding.reporting.hpfeeds_sink import HpfeedsSink
from heralding.reporting.hub import build_hub
from heralding.reporting.syslog_sink import SyslogSink


@pytest.mark.parametrize("failure", [ConnectionRefusedError("offline"), TimeoutError("slow")])
def test_hpfeeds_real_client_connection_failure_is_not_retried(monkeypatch, failure):
    connect = Mock(side_effect=failure)
    monkeypatch.setattr("heralding.reporting.hpfeeds_sink.socket.create_connection", connect)
    sink = HpfeedsSink("sessions", "auth", "localhost", 10000, "id", "secret")
    with pytest.raises(type(failure)):
        sink.open()
    connect.assert_called_once_with(("localhost", 10000), 3)
    assert sink._conn is None


def test_hpfeeds_real_client_auth_timeout_closes_socket(monkeypatch):
    sock = Mock()
    sock.recv.side_effect = TimeoutError("slow broker")
    monkeypatch.setattr(
        "heralding.reporting.hpfeeds_sink.socket.create_connection", Mock(return_value=sock)
    )
    from hpfeeds import FeedException

    sink = HpfeedsSink("sessions", "auth", "localhost", 10000, "id", "secret")
    with pytest.raises(FeedException, match="receive timeout"):
        sink.open()
    sock.close.assert_called_once()
    assert sink._conn is None


async def test_hpfeeds_real_client_auth_and_publish():
    from hpfeeds.protocol import OP_AUTH, OP_PUBLISH, Unpacker, msginfo, readpublish

    received = asyncio.Queue()

    async def broker(reader, writer):
        try:
            writer.write(msginfo("test-broker", b"challenge"))
            await writer.drain()
            unpacker = Unpacker()
            while data := await reader.read(4096):
                unpacker.feed(data)
                for message in unpacker:
                    await received.put(message)
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(broker, "127.0.0.1", 0)
    sink = HpfeedsSink(
        "sessions", "auth", "127.0.0.1", server.sockets[0].getsockname()[1], "id", "secret"
    )
    try:
        await asyncio.to_thread(sink.open)
        assert sink._conn.reconnect is False
        assert sink._conn.s.gettimeout() == 3
        await asyncio.to_thread(sink.handle_auth, {"username": "ä"})
        await asyncio.to_thread(sink.handle_session, {"session_id": "s"})
        opcode, _ = await asyncio.wait_for(received.get(), 3)
        assert opcode == OP_AUTH
        for channel, expected in [("auth", {"username": "ä"}), ("sessions", {"session_id": "s"})]:
            opcode, payload = await asyncio.wait_for(received.get(), 3)
            assert opcode == OP_PUBLISH
            ident, actual_channel, data = readpublish(payload)
            assert ident == "id" and actual_channel == channel
            assert json.loads(data) == expected
    finally:
        sink.close()
        server.close()
        await server.wait_closed()


def test_syslog_sanitizes_credentials(monkeypatch):
    output = Mock()
    monkeypatch.setattr("syslog.syslog", output)
    sink = SyslogSink("unknown-level")
    sink.handle_auth(
        {
            "source_ip": "127.0.0.1",
            "source_port": 123,
            "username": "u\r\nforged",
            "password": "\x00p",
        }
    )
    message = output.call_args.args[1]
    assert "\r" not in message and "\n" not in message and "\x00" not in message
    assert "forged" in message


def test_hpfeeds_reconnect_closes_failed_connection(monkeypatch):
    first, second = Mock(), Mock()
    first.publish.side_effect = OSError("disconnected")
    factory = Mock(side_effect=[first, second])
    monkeypatch.setattr("heralding.reporting.hpfeeds_sink._bounded_client", factory)
    sink = HpfeedsSink("sessions", "auth", "localhost", 10000, "id", "secret")
    sink.open()
    sink.handle_auth({"username": "ä"})
    first.close.assert_called_once()
    second.publish.assert_called_once()
    assert second.publish.call_args.args[0] == "auth"
    assert json.loads(second.publish.call_args.args[1]) == {"username": "ä"}
    sink.handle_session({"session_id": "s"})
    assert second.publish.call_args.args[0] == "sessions"
    sink.close()
    sink.close()
    second.close.assert_called_once()


def test_hpfeeds_recovers_after_reconnect_failure(monkeypatch):
    first, recovered = Mock(), Mock()
    first.publish.side_effect = OSError("disconnected")
    monkeypatch.setattr(
        "heralding.reporting.hpfeeds_sink._bounded_client",
        Mock(side_effect=[first, OSError("offline"), recovered]),
    )
    sink = HpfeedsSink("sessions", "auth", "localhost", 10000, "id", "secret")
    sink.open()
    with pytest.raises(OSError, match="offline"):
        sink.handle_auth({})
    sink.handle_auth({"username": "retry"})
    recovered.publish.assert_called_once()
    sink.close()


def test_curiosum_contract_periodic_ports_and_close(monkeypatch):
    sock, context = Mock(), Mock()
    context.socket.return_value = sock
    monkeypatch.setitem(
        sys.modules, "zmq", SimpleNamespace(Context=Mock(return_value=context), PUSH=8, NOBLOCK=1)
    )
    clock = Mock(return_value=10.0)
    monkeypatch.setattr("heralding.reporting.curiosum_sink.time.monotonic", clock)
    sink = CuriosumSink(12345)
    sink.open()
    sock.bind.assert_called_once_with("tcp://127.0.0.1:12345")
    sink.handle_session(
        {
            "session_id": "s",
            "destination_port": 21,
            "source_ip": "127.0.0.1",
            "source_port": 123,
            "session_ended": True,
        }
    )
    topic, encoded = sock.send_string.call_args.args[0].split(" ", 1)
    assert topic == "session_ended"
    assert json.loads(encoded)["SessionEnded"] is True
    sink.handle_listen_ports([21, 22])
    sink.tick()
    assert sock.send_string.call_args.args == ("listen_ports [21, 22]", 1)
    calls = sock.send_string.call_count
    sink.tick()
    assert sock.send_string.call_count == calls
    clock.return_value = 16.0
    sink.tick()
    assert sock.send_string.call_count == calls + 1
    sink.close()
    sock.close.assert_called_once_with(0)
    context.term.assert_called_once()


@pytest.mark.parametrize(
    "module,sink", [("hpfeeds", HpfeedsSink("s", "a", "h", 1, "i", "p")), ("zmq", CuriosumSink(1))]
)
def test_missing_optional_dependencies_explain_installation(monkeypatch, module, sink):
    monkeypatch.setitem(sys.modules, "hpfeeds.client" if module == "hpfeeds" else module, None)
    with pytest.raises(RuntimeError, match="uv sync --extra"):
        sink.open()


def test_build_hub_selects_optional_sinks():
    hub = build_hub(
        {
            "activity_logging": {
                "syslog": {"enabled": True},
                "hpfeeds": {
                    "enabled": True,
                    "session_channel": "s",
                    "auth_channel": "a",
                    "host": "h",
                    "port": 1,
                    "ident": "i",
                    "secret": "p",
                },
                "curiosum": {"enabled": True, "port": 12345},
            }
        }
    )
    assert [worker.sink.name for worker in hub._workers] == ["syslog", "hpfeeds", "curiosum"]


def test_drop_privileges_order_and_group_fallback(monkeypatch):
    calls = []
    monkeypatch.setattr(privileges.os, "getuid", Mock(side_effect=[0, 2000]))
    monkeypatch.setattr(privileges.os, "getgid", lambda: 2001)
    monkeypatch.setattr(
        privileges.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=2000, pw_gid=2001)
    )
    monkeypatch.setattr(privileges.pwd, "getpwuid", lambda _: SimpleNamespace(pw_name="nobody"))
    monkeypatch.setattr(privileges.grp, "getgrgid", lambda _: SimpleNamespace(gr_name="nobody"))
    lookup = Mock(side_effect=KeyError("no group"))
    monkeypatch.setattr(privileges.grp, "getgrnam", lookup)
    for action in ("setgroups", "setgid", "setuid"):
        monkeypatch.setattr(
            privileges.os, action, lambda value, name=action: calls.append((name, value))
        )
    privileges.drop_privileges()
    assert calls == [("setgroups", []), ("setgid", 2001), ("setuid", 2000)]
    assert lookup.call_count == 3


def test_nonroot_privileges_are_unchanged(monkeypatch):
    monkeypatch.setattr(privileges.os, "getuid", lambda: 2000)
    lookup = Mock()
    monkeypatch.setattr(privileges.pwd, "getpwnam", lookup)
    privileges.drop_privileges()
    lookup.assert_not_called()


def test_hub_start_failure_closes_already_open_sinks():
    from heralding.reporting.hub import ReportingHub

    working, failing = Mock(), Mock()
    failing.open.side_effect = OSError("no destination")
    hub = ReportingHub()
    hub.add_sink(working)
    hub.add_sink(failing)
    with pytest.raises(OSError, match="no destination"):
        hub.start()
    working.close.assert_called_once()
    failing.close.assert_called_once()
    assert all(not worker.is_alive() for worker in hub._workers)

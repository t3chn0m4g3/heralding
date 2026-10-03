import asyncio
import socket

from pyVoIP.VoIP import VoIPPhone

from heralding.capabilities import sip
from heralding.tests.conftest import make_options


async def _udp_server(sink, **options):
    cap = sip.Sip(make_options(**options))
    transport, _ = await cap.create_datagram_endpoint("127.0.0.1", 0)
    return transport, transport.get_extra_info("sockname")[1]


def _register(host, port, username, password, sink):
    """Standard client: pyVoIP sends REGISTER, answers the Digest challenge with the password
    and keeps retrying in the background; we stop it once our side has logged the attempt."""
    phone = VoIPPhone(host, port, username, password, myIP="127.0.0.1", sipPort=0)
    phone.start()
    try:
        sink.wait_for_auth(1, timeout=10)
    finally:
        phone.stop()


async def test_register_with_standard_client_is_logged(sink):
    transport, port = await _udp_server(sink)
    try:
        await asyncio.to_thread(_register, "127.0.0.1", port, "1001", "s3cret", sink)
    finally:
        transport.close()
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["username"] == "1001" and attempt["protocol"] == "sip"
    assert attempt["password_hash"].startswith("$sip$*")
    fields = attempt["password_hash"].split("*")
    assert len(fields) == 15
    assert fields[5:8] == ["REGISTER", "sip", "127.0.0.1;transport=UDP"]
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert any("REGISTER" in s["auxiliary_data"].get("commands", [""])[0] for s in ended)


def test_udp_token_bucket_limits_bursts_and_refills(monkeypatch):
    now = 100.0
    monkeypatch.setattr("heralding.capabilities.handlerbase.time.monotonic", lambda: now)
    cap = sip.Sip(make_options())
    source = "192.0.2.1"
    assert all(cap._allow(source) for _ in range(cap.BUCKET_SIZE))
    assert not cap._allow(source)
    assert cap._allow("192.0.2.2")
    now += 1 / cap.REFILL_PER_SECOND
    assert cap._allow(source)
    assert not cap._allow(source)
    now += 100
    assert all(cap._allow(source) for _ in range(cap.BUCKET_SIZE))
    assert not cap._allow(source)


async def test_tcp_register_with_library_generated_messages(serve, sink):
    from pyVoIP.SIP import SIPClient, SIPMessage

    host, port = await serve(sip.Sip(make_options()))

    def run():
        client = SIPClient(host, port, "2002", "secret", None, myIP="127.0.0.1", myPort=0)

        with socket.create_connection((host, port), timeout=5) as stream:
            replies = stream.makefile("rb")

            def exchange(message):
                # The library builds each request; only transport fragmentation is varied.
                payload = message.encode()
                stream.sendall(payload[:1])
                stream.sendall(payload[1:])
                response = bytearray()
                while True:
                    line = replies.readline()
                    if not line:
                        raise EOFError("missing SIP response")
                    response.extend(line)
                    if line == b"\r\n":
                        return bytes(response)

            challenge = SIPMessage(exchange(client.gen_first_response()))
            assert int(challenge.status) == 401
            assert int(SIPMessage(exchange(client.gen_register(challenge))).status) == 401
            replies.close()

    await asyncio.to_thread(run)
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["username"] == "2002"
    assert attempt["password_hash"].startswith("$sip$*")


def test_udp_bucket_eviction_keeps_recent_sources_and_global_limit(monkeypatch):
    now = 100.0
    monkeypatch.setattr("heralding.capabilities.handlerbase.time.monotonic", lambda: now)
    cap = sip.Sip(make_options())
    cap.MAX_SOURCES = 2
    assert cap._allow("192.0.2.1")
    assert cap._allow("192.0.2.2")
    assert cap._allow("192.0.2.1")
    assert cap._allow("192.0.2.3")
    assert list(cap._buckets) == ["192.0.2.1", "192.0.2.3"]
    cap = sip.Sip(make_options())
    assert all(cap._allow(f"192.0.2.{i}") for i in range(cap.GLOBAL_BUCKET_SIZE))
    assert not cap._allow("198.51.100.1")
    now += 1 / cap.GLOBAL_REFILL_PER_SECOND
    assert cap._allow("198.51.100.1")


async def test_udp_sessions_reused_and_expire_without_client_close(sink):
    from pyVoIP.SIP import SIPClient

    from heralding.capabilities.handlerbase import HandlerBase

    cap = sip.Sip(make_options(timeout=0))
    # Use a short fractional timeout for this lifecycle regression.
    cap.timeout = 0.05
    client = SIPClient("127.0.0.1", 5060, "alice", "secret", None, myPort=0)
    data = client.gen_first_response().encode()
    addr, local = ("192.0.2.1", 12345), ("127.0.0.1", 5060)
    assert cap.process_datagram(data, addr, local)
    assert cap.process_datagram(data, addr, local)
    assert len(cap.sessions) == 1
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert len(ended) == 1
    assert len(ended[0]["auxiliary_data"]["commands"]) == 2
    assert HandlerBase.global_sessions == 0

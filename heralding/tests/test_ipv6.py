import asyncio
import poplib
import socket

import pytest

from heralding.capabilities import pop3
from heralding.misc.session import normalize_ip
from heralding.tests.conftest import make_options


def test_normalize_ip():
    assert normalize_ip("::ffff:203.0.113.5") == "203.0.113.5"
    assert normalize_ip("2001:db8::1") == "2001:db8::1"
    assert normalize_ip("10.0.0.1") == "10.0.0.1"
    assert normalize_ip("not-an-ip") == "not-an-ip"


async def _pop3_attempt(host, port):
    def run():
        client = poplib.POP3(host, port, timeout=5)
        try:
            client.user("u")
            with pytest.raises(poplib.error_proto):
                client.pass_("p")
        finally:
            client.close()

    await asyncio.to_thread(run)


@pytest.mark.skipif(not socket.has_ipv6, reason="no IPv6 on this host")
async def test_dual_stack_source_ip_without_mapped_prefix(sink):
    cap = pop3.Pop3(make_options(max_attempts=3, banner="+OK"))
    # Bind IPv4 first and retain its socket while adding IPv6 on the same port.
    server = await cap.create_server("0.0.0.0", 0)
    port = server.sockets[0].getsockname()[1]
    ipv6 = await cap.create_server("::", port)
    try:
        await _pop3_attempt("127.0.0.1", port)
        attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
        assert attempt["source_ip"] == "127.0.0.1"
        assert attempt["destination_ip"] == "127.0.0.1"
        await _pop3_attempt("::1", port)
        attempt = (await asyncio.to_thread(sink.wait_for_auth, 2))[1]
        assert attempt["source_ip"] == "::1"
    finally:
        server.close()
        ipv6.close()
        server.close_clients()
        ipv6.close_clients()
        await server.wait_closed()
        await ipv6.wait_closed()


async def test_bind_host_list_binds_all(sink):
    cap = pop3.Pop3(make_options(max_attempts=3, banner="+OK"))
    server = await cap.create_server(["127.0.0.1", "::1" if socket.has_ipv6 else "127.0.0.1"], 0)
    try:
        families = {s.family for s in server.sockets}
        assert socket.AF_INET in families
        if socket.has_ipv6:
            assert socket.AF_INET6 in families
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.skipif(not socket.has_ipv6, reason="no IPv6 on this host")
async def test_udp_endpoint_on_ipv6_is_v6only(sink):
    """asyncio sets IPV6_V6ONLY for TCP but not for UDP; without it "::" collides with 0.0.0.0."""
    from heralding.capabilities import sip

    cap = sip.Sip(make_options())
    transport, _ = await cap.create_datagram_endpoint("::", 0)
    ipv4_transport = None
    try:
        sock = transport.get_extra_info("socket")
        assert sock.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 1
        port = transport.get_extra_info("sockname")[1]
        ipv4_transport, _ = await cap.create_datagram_endpoint("0.0.0.0", port)
    finally:
        if ipv4_transport is not None:
            ipv4_transport.close()
        transport.close()


def test_ipv6_entries_are_skipped_when_the_host_has_no_ipv6(monkeypatch, caplog):
    from heralding import honeypot

    monkeypatch.setattr(honeypot, "_can_bind", lambda host: False)
    assert honeypot.usable_bind_hosts(["0.0.0.0", "::"]) == "0.0.0.0"
    assert "not listening on ::" in caplog.text
    assert honeypot.usable_bind_hosts("::") == "::"  # nothing left: keep it and fail loudly
    assert honeypot.usable_bind_hosts("0.0.0.0") == "0.0.0.0"
    monkeypatch.setattr(honeypot, "_can_bind", lambda host: True)
    assert honeypot.usable_bind_hosts(["0.0.0.0", "::"]) == ["0.0.0.0", "::"]


def test_default_config_is_dual_stack():
    import importlib.resources

    import yaml

    text = importlib.resources.files("heralding").joinpath("heralding.yml").read_text()
    assert yaml.safe_load(text)["bind_host"] == ["0.0.0.0", "::"]

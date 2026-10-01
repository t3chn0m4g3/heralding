import asyncio
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
    reader, writer = await asyncio.open_connection(host, port)
    await reader.readline()
    writer.write(b"USER u\r\nPASS p\r\n")
    await writer.drain()
    await reader.readline()
    await reader.readline()
    writer.close()


@pytest.mark.skipif(not socket.has_ipv6, reason="no IPv6 on this host")
async def test_dual_stack_source_ip_without_mapped_prefix(sink):
    cap = pop3.Pop3(make_options(max_attempts=3, banner="+OK"))
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = await cap.create_server(["0.0.0.0", "::"], port)
    assert {s.getsockname()[1] for s in server.sockets} == {port}  # same port on both families
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
        server.close_clients()
        await server.wait_closed()


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

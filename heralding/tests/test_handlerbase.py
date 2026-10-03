import asyncio

import pytest

from heralding.capabilities import pop3
from heralding.capabilities.handlerbase import HandlerBase
from heralding.tests.conftest import make_options


@pytest.fixture
def restore_limits():
    yield
    HandlerBase.configure_limits(max_sessions=800, max_sessions_per_ip=50)


async def _wait_sessions_zero():
    for _ in range(100):
        if HandlerBase.global_sessions == 0:
            return
        await asyncio.sleep(0.05)


async def test_global_limit_closes_socket(serve, sink, restore_limits):
    HandlerBase.configure_limits(max_sessions=1, max_sessions_per_ip=50)
    cap = pop3.Pop3(make_options(max_attempts=3, banner="+OK"))
    host, port = await serve(cap)
    r1, w1 = await asyncio.open_connection(host, port)
    assert (await r1.readline()).startswith(b"+OK")
    r2, w2 = await asyncio.open_connection(host, port)
    assert await asyncio.wait_for(r2.read(), 5) == b""  # closed without banner
    w1.close()
    w2.close()


async def test_per_ip_limit(serve, sink, restore_limits):
    HandlerBase.configure_limits(max_sessions=800, max_sessions_per_ip=1)
    cap = pop3.Pop3(make_options(max_attempts=3, banner="+OK"))
    host, port = await serve(cap)
    r1, w1 = await asyncio.open_connection(host, port)
    await r1.readline()
    r2, w2 = await asyncio.open_connection(host, port)
    assert await asyncio.wait_for(r2.read(), 5) == b""
    w1.close()
    w2.close()


async def test_session_counter_returns_to_zero(serve, sink):
    cap = pop3.Pop3(make_options(max_attempts=3, banner="+OK"))
    host, port = await serve(cap)

    def client():
        import poplib

        conn = poplib.POP3(host, port, timeout=5)
        conn.quit()

    await asyncio.to_thread(client)
    await _wait_sessions_zero()
    assert HandlerBase.global_sessions == 0
    assert not HandlerBase.sessions_per_ip


async def test_create_server_read_limit_is_16k(serve, sink):
    cap = pop3.Pop3(make_options(max_attempts=3, banner="+OK"))
    host, port = await serve(cap)  # serve() goes through cap.create_server()
    r, w = await asyncio.open_connection(host, port)
    await r.readline()
    w.write(b"A" * 20000 + b"\r\n")
    await w.drain()
    assert await asyncio.wait_for(r.read(), 5) == b""  # LimitOverrun -> session closed
    w.close()
    await _wait_sessions_zero()
    assert HandlerBase.global_sessions == 0


def test_limit_key_groups_ipv6_by_64():
    from heralding.capabilities.handlerbase import limit_key

    assert limit_key("203.0.113.5") == "203.0.113.5"
    assert limit_key("::ffff:203.0.113.5") == "203.0.113.5"
    assert limit_key("2001:db8:1:2::1") == limit_key("2001:db8:1:2:ffff::9") == "2001:db8:1:2::/64"
    assert limit_key("2001:db8:1:3::1") != limit_key("2001:db8:1:2::1")


def test_per_ip_limit_counts_an_ipv6_64_as_one_source(sink, restore_limits):
    HandlerBase.configure_limits(max_sessions=800, max_sessions_per_ip=2)
    cap = pop3.Pop3(make_options(max_attempts=3, banner="+OK"))
    local = ("2001:db8:ffff::1", 110)
    sessions = [cap.create_session((f"2001:db8:1:2::{i}", 4000 + i), local) for i in (1, 2)]
    try:
        assert cap._limit_reached(("2001:db8:1:2::99", 5000))
        assert not cap._limit_reached(("2001:db8:1:3::1", 5000))
    finally:
        for session in sessions:
            cap.close_session(session)
    assert HandlerBase.global_sessions == 0
    assert not HandlerBase.sessions_per_ip


async def test_udp_sessions_do_not_use_the_tcp_session_pool(sink, restore_limits):
    from pyVoIP.SIP import SIPClient

    from heralding.capabilities import sip

    HandlerBase.configure_limits(max_sessions=1, max_sessions_per_ip=1)
    cap = sip.Sip(make_options())
    cap.MAX_UDP_SESSIONS = 3
    data = SIPClient("127.0.0.1", 5060, "a", "b", None, myPort=0).gen_first_response().encode()
    local = ("127.0.0.1", 5060)
    try:
        replies = [cap.process_datagram(data, (f"192.0.2.{i}", 5060), local) for i in range(5)]
        assert [bool(r) for r in replies] == [True, True, True, False, False]
        assert HandlerBase.global_sessions == 0
        assert not cap._limit_reached(("198.51.100.1", 1234))
    finally:
        cap.close_datagram_sessions()

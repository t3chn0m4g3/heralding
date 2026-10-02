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

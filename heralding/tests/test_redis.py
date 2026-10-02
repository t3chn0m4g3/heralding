import asyncio

import pytest
import redis as redis_client

from heralding.capabilities import redis
from heralding.tests.conftest import make_options


def _client(host, port, **kw):
    return redis_client.Redis(
        host=host, port=port, socket_timeout=5, socket_connect_timeout=5, **kw
    )


async def test_password_only_auth_is_logged(serve, sink):
    host, port = await serve(redis.Redis(make_options()))

    def run():
        with pytest.raises(redis_client.AuthenticationError):
            _client(host, port, password="pw").ping()

    await asyncio.to_thread(run)
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("default", "pw")
    assert attempt["protocol"] == "redis"


async def test_username_and_password_are_logged(serve, sink):
    host, port = await serve(redis.Redis(make_options()))

    def run():
        with pytest.raises(redis_client.AuthenticationError):
            _client(host, port, username="alice", password="pw").ping()

    await asyncio.to_thread(run)
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("alice", "pw")


async def test_unauthenticated_command_gets_noauth_and_is_recorded(serve, sink):
    host, port = await serve(redis.Redis(make_options()))

    def run():
        with pytest.raises(redis_client.AuthenticationError):
            _client(host, port).ping()

    await asyncio.to_thread(run)
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(b"*1\r\n$4\r\nQUIT\r\n")
    await writer.drain()
    assert await reader.readline() == b"+OK\r\n"
    writer.close()
    ended = await asyncio.to_thread(sink.wait_for_session_end, 2)
    # redis-py sends CLIENT SETINFO before PING and stops at the first NOAUTH; both sessions
    # must have their command lines recorded
    recorded = [s["auxiliary_data"].get("commands", []) for s in ended]
    assert all(recorded)
    assert any("QUIT" in cmds for cmds in recorded)


async def test_inline_protocol_and_version_from_persona(serve, sink):
    host, port = await serve(redis.Redis(make_options()))
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(b"AUTH s3cret\r\n")
    await writer.drain()
    assert (await reader.readline()).startswith(b"-WRONGPASS")
    writer.write(b"INFO server\r\n")
    await writer.drain()
    assert (await reader.readline()).startswith(b"-NOAUTH")
    writer.close()
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["password"] == "s3cret"


async def test_oversized_bulk_is_a_client_error(serve, sink):
    host, port = await serve(redis.Redis(make_options(timeout=2)))
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(b"*2\r\n$4\r\nAUTH\r\n$99999999\r\n")
    await writer.drain()
    assert await asyncio.wait_for(reader.read(), 5) == b""  # closed, no reply, no traceback
    writer.close()

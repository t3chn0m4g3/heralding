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


def _connection(host, port):
    # RESP2 and no client metadata let us exercise commands on one unauthenticated connection.
    return redis_client.Connection(
        host=host,
        port=port,
        socket_timeout=5,
        socket_connect_timeout=5,
        protocol=2,
        driver_info=None,
    )


async def test_unauthenticated_command_gets_noauth_and_is_recorded(serve, sink):
    host, port = await serve(redis.Redis(make_options()))

    def run():
        with pytest.raises(redis_client.AuthenticationError):
            _client(host, port).ping()
        conn = _connection(host, port)
        try:
            conn.connect()
            conn.send_command("QUIT")
            assert conn.read_response(disconnect_on_error=False) == b"OK"
        finally:
            conn.disconnect()

    await asyncio.to_thread(run)
    ended = await asyncio.to_thread(sink.wait_for_session_end, 2)
    recorded = [event["auxiliary_data"]["commands"] for event in ended]
    assert all(recorded)
    assert ["QUIT"] in recorded


async def test_auth_and_info_with_standard_client(serve, sink):
    host, port = await serve(redis.Redis(make_options()))

    def run():
        conn = _connection(host, port)
        try:
            conn.connect()
            conn.send_packed_command(
                conn.pack_commands(
                    [
                        ("AUTH", "s3cret"),
                        ("INFO", "server"),
                        ("QUIT",),
                    ]
                )
            )
            sink.wait_for_session_end(1)
        finally:
            conn.disconnect()

    await asyncio.to_thread(run)
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["password"] == "s3cret"


async def test_attempts_per_connection_are_capped(serve, sink):
    host, port = await serve(redis.Redis(make_options(max_attempts=3)))

    def run():
        conn = _connection(host, port)
        try:
            conn.connect()
            # Let redis-py encode a batch; wait for the server to end the session before
            # disconnecting the client. Without the server limit this wait times out.
            conn.send_packed_command(conn.pack_commands([("AUTH", f"pw{i}") for i in range(10)]))
            sink.wait_for_session_end(1)
        finally:
            conn.disconnect()

    await asyncio.to_thread(run)
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert ended[0]["num_auth_attempts"] == 3
    assert len(sink.auth) == 3

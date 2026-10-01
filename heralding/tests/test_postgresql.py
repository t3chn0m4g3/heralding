import asyncio
import struct

import psycopg

from heralding.capabilities import postgresql
from heralding.tests.conftest import make_options


async def test_invalid_login(serve, sink):
    cap = postgresql.PostgreSQL(make_options())
    host, port = await serve(cap)

    def run():
        try:
            psycopg.connect(
                host=host,
                port=port,
                user="scott",
                password="tiger",
                dbname="postgres",
                connect_timeout=5,
                gssencmode="disable",
            )
        except psycopg.OperationalError as exc:
            return exc
        return None

    exc = await asyncio.to_thread(run)
    assert isinstance(exc, psycopg.OperationalError)
    assert 'password authentication failed for user "scott"' in str(exc)
    attempts = await asyncio.to_thread(sink.wait_for_auth, 1)
    assert (attempts[0]["username"], attempts[0]["password"]) == ("scott", "tiger")


async def test_postgresql_without_sslrequest(serve, sink):
    host, port = await serve(postgresql.PostgreSQL(make_options()))
    reader, writer = await asyncio.open_connection(host, port)
    params = b"user\x00alice\x00database\x00db\x00\x00"
    startup = struct.pack(">I", 8 + len(params)) + struct.pack(">I", 196608) + params
    writer.write(startup)
    await writer.drain()
    assert await reader.readexactly(9) == b"R" + struct.pack(">II", 8, 3)
    pw = b"pw\x00"
    writer.write(b"p" + struct.pack(">I", 4 + len(pw)) + pw)
    await writer.drain()
    assert await reader.readexactly(1) == b"E"
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("alice", "pw")
    writer.close()


async def test_postgresql_gssenc_then_ssl_then_startup(serve, sink):
    host, port = await serve(postgresql.PostgreSQL(make_options(timeout=2)))
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(struct.pack(">II", 8, 80877104))  # GSSENCRequest
    await writer.drain()
    assert await reader.readexactly(1) == b"N"
    writer.write(struct.pack(">II", 8, 80877103))  # SSLRequest
    await writer.drain()
    assert await reader.readexactly(1) == b"N"
    params = b"user\x00bob\x00\x00"
    writer.write(struct.pack(">I", 8 + len(params)) + struct.pack(">I", 196608) + params)
    await writer.drain()
    assert (await reader.readexactly(1)) == b"R"
    writer.close()

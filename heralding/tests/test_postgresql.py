import asyncio

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


async def test_client_without_tls_negotiation_is_logged(serve, sink):
    host, port = await serve(postgresql.PostgreSQL(make_options()))

    def run():
        try:
            psycopg.connect(
                host=host, port=port, user="alice", password="pw", dbname="db",
                connect_timeout=5, sslmode="disable", gssencmode="disable",
            )  # fmt: skip
        except psycopg.OperationalError as exc:
            return exc
        return None

    assert isinstance(await asyncio.to_thread(run), psycopg.OperationalError)
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("alice", "pw")

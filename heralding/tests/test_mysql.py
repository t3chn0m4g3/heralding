import asyncio

import pymysql

from heralding.capabilities import mysql
from heralding.tests.conftest import make_options


async def test_invalid_login(serve, sink):
    cap = mysql.MySQL(make_options())
    host, port = await serve(cap)

    def run():
        try:
            pymysql.connect(
                host=host,
                port=port,
                user="tuser",
                password="tpass",
                database="testdb",
                connect_timeout=5,
            )
        except pymysql.err.OperationalError as exc:
            return exc
        return None

    exc = await asyncio.to_thread(run)
    assert isinstance(exc, pymysql.err.OperationalError)
    assert exc.args[0] == 1045
    assert "Access denied for user 'tuser'@'127.0.0.1' (using password: YES)" in exc.args[1]
    attempts = await asyncio.to_thread(sink.wait_for_auth, 1)
    assert attempts[0]["username"] == "tuser"

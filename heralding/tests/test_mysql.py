import asyncio
import hashlib

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


async def test_mysql_logs_salt_and_hashcat_11200(serve, sink):
    host, port = await serve(mysql.MySQL(make_options()))

    def run():
        try:
            pymysql.connect(host=host, port=port, user="root", password="secret", connect_timeout=5)
        except pymysql.err.OperationalError as exc:
            return exc.args[0]
        return None

    assert await asyncio.to_thread(run) == 1045
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["username"] == "root"
    assert attempt["password"] == ""
    tag, rest = attempt["password_hash"][1:].split("$", 1)
    assert tag == "mysqlna"
    salt_hex, scramble_hex = rest.split("*")
    salt, scramble = bytes.fromhex(salt_hex), bytes.fromhex(scramble_hex)
    assert len(salt) == 20 and len(scramble) == 20
    # mysql_native_password: SHA1(pw) XOR SHA1(salt + SHA1(SHA1(pw)))
    s1 = hashlib.sha1(b"secret").digest()
    s2 = hashlib.sha1(salt + hashlib.sha1(s1).digest()).digest()
    assert bytes(a ^ b for a, b in zip(s1, s2, strict=True)) == scramble


async def test_mysql_thread_id_is_random(serve, sink):
    host, port = await serve(mysql.MySQL(make_options()))
    ids = set()
    for _ in range(3):
        reader, writer = await asyncio.open_connection(host, port)
        header = await reader.readexactly(4)
        payload = await reader.readexactly(int.from_bytes(header[:3], "little"))
        # protocol version (1) + server version (NUL terminated) + thread id (4)
        ver_end = payload.index(b"\x00", 1)
        ids.add(int.from_bytes(payload[ver_end + 1 : ver_end + 5], "little"))
        writer.close()
    assert len(ids) == 3
    assert 4321 not in ids

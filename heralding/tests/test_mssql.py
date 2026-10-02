import asyncio

import pytds
import pytest

from heralding.capabilities import mssql
from heralding.capabilities.handlerbase import HandlerBase
from heralding.tests.conftest import make_options


async def test_login_is_refused_and_logged(serve, sink):
    host, port = await serve(mssql.Mssql(make_options()))

    def run():
        with pytest.raises(pytds.Error) as excinfo:  # pytds maps 18456 to OperationalError
            pytds.connect(
                server=host,
                port=port,
                user="sa",
                password="P@ssw0rd!",
                database="master",
                login_timeout=5,
                timeout=5,
                appname="probe-app",
            )
        return str(excinfo.value)

    message = await asyncio.to_thread(run)
    assert "Login failed for user 'sa'" in message
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("sa", "P@ssw0rd!")
    assert attempt["protocol"] == "mssql"
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    aux = ended[0]["auxiliary_data"]
    assert aux["app_name"] == "probe-app"
    assert aux["database"] == "master"
    assert aux["client_hostname"]


async def test_non_utf16_garbage_login_is_a_client_error(serve, sink):
    host, port = await serve(mssql.Mssql(make_options(timeout=2)))
    reader, writer = await asyncio.open_connection(host, port)
    # PRELOGIN packet header (type 0x12) with a nonsense body, then junk
    writer.write(b"\x12\x01\x00\x0c\x00\x00\x01\x00\xff\xff\xff\xff")
    await writer.drain()
    try:
        await asyncio.wait_for(reader.read(4096), 2)
    except TimeoutError, ConnectionError:
        pass
    writer.write(b"\x10\x01\x00\x10\x00\x00\x01\x00" + b"\x00" * 8)
    await writer.drain()
    assert await asyncio.wait_for(reader.read(), 5) == b""
    writer.close()
    for _ in range(40):
        if HandlerBase.global_sessions == 0:
            break
        await asyncio.sleep(0.05)
    assert HandlerBase.global_sessions == 0


async def test_prelogin_reports_persona_version_and_no_encryption(serve, sink):
    host, port = await serve(mssql.Mssql(make_options()))
    reader, writer = await asyncio.open_connection(host, port)
    # PRELOGIN with VERSION and ENCRYPTION options
    options = b"\x00\x00\x0b\x00\x06" + b"\x01\x00\x11\x00\x01" + b"\xff"
    body = options + b"\x00\x00\x00\x00\x00\x00" + b"\x00"
    packet = b"\x12\x01" + (8 + len(body)).to_bytes(2, "big") + b"\x00\x00\x01\x00" + body
    writer.write(packet)
    await writer.drain()
    header = await asyncio.wait_for(reader.readexactly(8), 5)
    assert header[0] == 0x04  # tabular response
    length = int.from_bytes(header[2:4], "big")
    resp = await asyncio.wait_for(reader.readexactly(length - 8), 5)
    # ENCRYPTION option (token 1) must be ENCRYPT_NOT_SUP (2)
    pos = 0
    enc = None
    while resp[pos] != 0xFF:
        token, offset, size = (
            resp[pos],
            int.from_bytes(resp[pos + 1 : pos + 3], "big"),
            int.from_bytes(resp[pos + 3 : pos + 5], "big"),
        )
        if token == 1:
            enc = resp[offset : offset + size]
        pos += 5
    assert enc == b"\x02"
    writer.close()

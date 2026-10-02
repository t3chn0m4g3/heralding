import asyncio
import ftplib

import pytest

from heralding.capabilities import ftp, ftps
from heralding.capabilities.handlerbase import HandlerBase
from heralding.tests.conftest import make_options


def _options():
    return make_options(max_attempts=3, banner="Test FTP", syst_type="UNIX Type: L8")


async def test_implicit_ftps_logs_credentials(serve, sink, server_ssl_context, client_ssl_context):
    host, port = await serve(ftps.Ftps(_options()), server_ssl_context)

    def run():
        client = ftplib.FTP_TLS(context=client_ssl_context)
        # implicit TLS: wrap the socket before the banner
        client.sock = client_ssl_context.wrap_socket(
            __import__("socket").create_connection((host, port), 5), server_hostname=host
        )
        client.file = client.sock.makefile("r", encoding=client.encoding)
        client.welcome = client.getresp()
        with pytest.raises(ftplib.error_perm):
            client.login("imp", "licit")
        client.quit()

    await asyncio.to_thread(run)
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("imp", "licit")
    assert attempt["protocol"] == "ftps"


async def test_explicit_auth_tls_on_plain_ftp(
    serve, sink, tmp_path, monkeypatch, client_ssl_context
):
    monkeypatch.chdir(tmp_path)  # ftp.pem is created on demand for AUTH TLS
    host, port = await serve(ftp.ftp(_options()))

    def run():
        client = ftplib.FTP_TLS(context=client_ssl_context)
        client.connect(host, port, timeout=5)
        client.auth()  # AUTH TLS
        with pytest.raises(ftplib.error_perm):
            client.login("exp", "licit")
        client.quit()

    await asyncio.to_thread(run)
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("exp", "licit")
    assert attempt["protocol"] == "ftp"
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert ended[0]["auxiliary_data"]["starttls"] is True
    assert "AUTH TLS" in ended[0]["auxiliary_data"]["commands"]


async def test_feat_advertises_auth_tls(serve, sink, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    host, port = await serve(ftp.ftp(_options()))
    reader, writer = await asyncio.open_connection(host, port)
    await reader.readline()
    writer.write(b"FEAT\r\n")
    await writer.drain()
    lines = b""
    while not lines.endswith(b"211 End\r\n"):
        lines += await asyncio.wait_for(reader.readline(), 5)
    assert b" AUTH TLS\r\n" in lines
    writer.close()


async def test_auth_tls_garbage_is_a_client_error(serve, sink, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    host, port = await serve(
        ftp.ftp(make_options(max_attempts=3, banner="b", syst_type="UNIX", timeout=5))
    )
    reader, writer = await asyncio.open_connection(host, port)
    await reader.readline()
    writer.write(b"AUTH TLS\r\n")
    await writer.drain()
    assert (await reader.readline()).startswith(b"234")
    writer.write(b"USER plaintext-after-auth\r\n")
    await writer.drain()
    assert await asyncio.wait_for(reader.read(), 5) == b""
    writer.close()
    for _ in range(40):
        if HandlerBase.global_sessions == 0:
            break
        await asyncio.sleep(0.05)
    assert HandlerBase.global_sessions == 0

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


async def test_explicit_auth_tls_on_plain_ftp(serve, sink, server_ssl_context, client_ssl_context):
    cap = ftp.ftp(_options())
    cap.starttls_context = server_ssl_context
    host, port = await serve(cap)

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


async def test_feat_advertises_auth_tls(serve, sink, server_ssl_context):
    cap = ftp.ftp(_options())
    cap.starttls_context = server_ssl_context
    host, port = await serve(cap)

    def run():
        with ftplib.FTP() as client:
            client.connect(host, port, timeout=5)
            assert " AUTH TLS" in client.sendcmd("FEAT")

    await asyncio.to_thread(run)


async def test_disconnect_after_auth_tls_cleans_up_session(serve, sink, server_ssl_context):
    cap = ftp.ftp(_options())
    cap.starttls_context = server_ssl_context
    host, port = await serve(cap)

    def run():
        client = ftplib.FTP()
        client.connect(host, port, timeout=5)
        try:
            assert client.sendcmd("AUTH TLS").startswith("234")
        finally:
            client.close()

    await asyncio.to_thread(run)
    await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert HandlerBase.global_sessions == 0

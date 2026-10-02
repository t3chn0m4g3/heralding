import asyncio
import ftplib

import pytest

from heralding.capabilities import ftp
from heralding.tests.conftest import make_options


async def test_login(serve, sink):
    cap = ftp.ftp(make_options(max_attempts=3, banner="test banner", syst_type="Test Type"))
    host, port = await serve(cap)

    def ftp_login():
        client = ftplib.FTP()
        client.connect(host, port, 5)
        try:
            client.login("james", "bond")
        except ftplib.error_perm:
            client.quit()
            return True
        return False

    assert await asyncio.to_thread(ftp_login)
    attempts = await asyncio.to_thread(sink.wait_for_auth, 1)
    assert attempts[0]["username"] == "james"
    assert attempts[0]["password"] == "bond"
    assert attempts[0]["protocol"] == "ftp"


async def test_ftp_closes_after_max_attempts_and_logs_latin1(serve, sink):
    cap = ftp.ftp(make_options(max_attempts=2, banner="b", syst_type="UNIX"))
    host, port = await serve(cap)

    def run():
        client = ftplib.FTP(encoding="latin1")
        client.connect(host, port, timeout=5)
        try:
            for _ in range(2):
                with pytest.raises(ftplib.error_perm):
                    client.login("u", "pä")
            with pytest.raises(EOFError):
                client.getresp()
        finally:
            client.close()

    await asyncio.to_thread(run)
    attempts = await asyncio.to_thread(sink.wait_for_auth, 2)
    assert attempts[0]["password"] == "p\\xe4"

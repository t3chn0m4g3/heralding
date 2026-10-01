import asyncio
import ftplib

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
    reader, writer = await asyncio.open_connection(host, port)
    await reader.readline()
    for _ in range(2):
        writer.write(b"USER u\r\n")
        await writer.drain()
        await reader.readline()
        writer.write(b"PASS p\xe4\r\n")
        await writer.drain()
        assert (await reader.readline()).startswith(b"530")
    assert await asyncio.wait_for(reader.read(), 5) == b""  # server closed the connection
    attempts = await asyncio.to_thread(sink.wait_for_auth, 2)
    assert attempts[0]["password"] == "p\\xe4"
    writer.close()

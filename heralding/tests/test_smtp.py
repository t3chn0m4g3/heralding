import asyncio
import base64
import hmac
import smtplib

from heralding.capabilities import smtp
from heralding.tests.conftest import make_options


def _options():
    return make_options(banner="Test", fqdn="test.local")


async def test_connection_and_ehlo(serve, sink):
    host, port = await serve(smtp.smtp(_options()))

    def run():
        client = smtplib.SMTP(host, port, local_hostname="localhost", timeout=5)
        code, _ = client.ehlo()
        client.quit()
        return code

    assert await asyncio.to_thread(run) == 250


async def test_auth_plain_reject(serve, sink):
    host, port = await serve(smtp.smtp(_options()))

    def run():
        client = smtplib.SMTP(host, port, local_hostname="localhost", timeout=5)
        arg = base64.b64encode(b"\0test\0test").decode()
        code, _ = client.docmd("AUTH", "PLAIN " + arg)
        client.quit()
        return code

    assert await asyncio.to_thread(run) == 535
    attempts = await asyncio.to_thread(sink.wait_for_auth, 1)
    assert (attempts[0]["username"], attempts[0]["password"]) == ("test", "test")


async def test_auth_login_reject(serve, sink):
    host, port = await serve(smtp.smtp(_options()))

    def run():
        client = smtplib.SMTP(host, port, local_hostname="localhost", timeout=5)
        client.docmd("AUTH", "LOGIN")
        client.docmd(base64.b64encode(b"user1").decode())
        code, _ = client.docmd(base64.b64encode(b"pass1").decode())
        client.quit()
        return code

    assert await asyncio.to_thread(run) == 535
    attempts = await asyncio.to_thread(sink.wait_for_auth, 1)
    assert (attempts[0]["username"], attempts[0]["password"]) == ("user1", "pass1")


async def test_auth_cram_md5_reject(serve, sink):
    host, port = await serve(smtp.smtp(_options()))

    def run():
        client = smtplib.SMTP(host, port, local_hostname="localhost", timeout=5)
        code, resp = client.docmd("AUTH", "CRAM-MD5")
        assert code == 334
        challenge = base64.decodebytes(resp)
        digest = hmac.HMAC(b"test", challenge, digestmod="md5").hexdigest()
        response = base64.b64encode(b"test " + digest.encode()).decode()
        code, _ = client.docmd(response)
        client.quit()
        return code

    assert await asyncio.to_thread(run) == 535
    attempts = await asyncio.to_thread(sink.wait_for_auth, 1)
    assert attempts[0]["username"] == "test"

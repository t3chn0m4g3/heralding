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


async def test_auth_mechanism_case_insensitive(serve, sink):
    host, port = await serve(smtp.smtp(_options()))

    def run():
        client = smtplib.SMTP(host, port, local_hostname="localhost", timeout=5)
        client.ehlo("x")
        code, _ = client.docmd("AUTH", "plain " + base64.b64encode(b"\0u\0p").decode())
        client.close()
        return code

    assert await asyncio.to_thread(run) == 535
    attempts = await asyncio.to_thread(sink.wait_for_auth, 1)
    assert attempts[0]["password"] == "p"


async def test_bad_base64_is_501(serve, sink):
    host, port = await serve(smtp.smtp(_options()))

    def run():
        client = smtplib.SMTP(host, port, local_hostname="localhost", timeout=5)
        client.ehlo("x")
        code, _ = client.docmd("AUTH", "PLAIN !!!notbase64")
        client.close()
        return code

    assert await asyncio.to_thread(run) == 501


async def test_cram_md5_single_535_and_hashcat_10200(serve, sink):
    host, port = await serve(smtp.smtp(_options()))

    def run():
        client = smtplib.SMTP(host, port, local_hostname="localhost", timeout=5)
        client.ehlo("x")
        code, resp = client.docmd("AUTH", "CRAM-MD5")
        assert code == 334
        challenge = base64.b64decode(resp)
        digest = hmac.new(b"secret", challenge, "md5").hexdigest()
        code, _ = client.docmd(base64.b64encode(f"user {digest}".encode()).decode())
        # exactly one 535: the next command must get its own, normal reply
        noop_code, _ = client.noop()
        client.close()
        return code, noop_code, challenge, digest

    code, noop_code, challenge, digest = await asyncio.to_thread(run)
    assert code == 535
    assert noop_code == 250
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["username"] == "user"
    tag, b64_chal, b64_resp = attempt["password_hash"].split("$")[1:]
    assert tag == "cram_md5"
    assert base64.b64decode(b64_chal) == challenge
    assert base64.b64decode(b64_resp) == f"user {digest}".encode()
    # the logged material verifies against the known password
    assert hmac.new(b"secret", base64.b64decode(b64_chal), "md5").hexdigest() == digest


async def test_ehlo_advertises_size_limit(serve, sink):
    host, port = await serve(smtp.smtp(_options()))

    def run():
        client = smtplib.SMTP(host, port, local_hostname="localhost", timeout=5)
        client.ehlo("x")
        features = dict(client.esmtp_features)  # quit() clears them
        client.quit()
        return features

    features = await asyncio.to_thread(run)
    assert features.get("size") == "1048576"
    assert "auth" in features


def test_explicit_fqdn_is_not_overwritten_by_lookup():
    smtp.set_fqdn("", source="lookup")
    smtp.smtp(make_options(banner="b", fqdn="fixed.example"))
    smtp.set_fqdn("looked-up.example", source="lookup")
    assert smtp.SMTPHandler.fqdn == "fixed.example"
    smtp.set_fqdn("", source="config")  # reset pin for other tests
    smtp.set_fqdn("", source="lookup")

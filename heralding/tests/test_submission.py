import asyncio
import base64
import smtplib

from heralding.capabilities import submission
from heralding.capabilities.handlerbase import HandlerBase
from heralding.tests.conftest import make_options


async def _server(serve, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # submission.pem is created in the working directory
    cap = submission.Submission(make_options(banner="Test", fqdn="mail.test.local"))
    return await serve(cap)


async def test_starttls_then_auth_plain_is_logged(
    serve, sink, tmp_path, monkeypatch, client_ssl_context
):
    host, port = await _server(serve, tmp_path, monkeypatch)

    def run():
        client = smtplib.SMTP(host, port, local_hostname="localhost", timeout=5)
        code, _ = client.ehlo("x")
        assert code == 250 and client.has_extn("starttls")
        code, _ = client.starttls(context=client_ssl_context)
        assert code == 220
        client.ehlo("x")
        code, _ = client.docmd("AUTH", "PLAIN " + base64.b64encode(b"\0sub\0secret").decode())
        client.quit()
        return code

    assert await asyncio.to_thread(run) == 535
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("sub", "secret")
    assert attempt["protocol"] == "submission"
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert ended[0]["auxiliary_data"]["starttls"] is True


async def test_auth_before_starttls_is_also_logged(serve, sink, tmp_path, monkeypatch):
    host, port = await _server(serve, tmp_path, monkeypatch)

    def run():
        client = smtplib.SMTP(host, port, local_hostname="localhost", timeout=5)
        client.ehlo("x")
        code, _ = client.docmd("AUTH", "LOGIN " + base64.b64encode(b"plainuser").decode())
        assert code == 334
        code, _ = client.docmd(base64.b64encode(b"plainpass").decode())
        client.quit()
        return code

    assert await asyncio.to_thread(run) == 535
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("plainuser", "plainpass")
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert ended[0]["auxiliary_data"]["starttls"] is False


async def test_tls_garbage_after_starttls_is_a_client_error(serve, sink, tmp_path, monkeypatch):
    host, port = await _server(serve, tmp_path, monkeypatch)
    reader, writer = await asyncio.open_connection(host, port)
    await reader.readline()
    writer.write(b"EHLO x\r\n")
    await writer.drain()
    while not (await reader.readline()).startswith(b"250 "):
        pass
    writer.write(b"STARTTLS\r\n")
    await writer.drain()
    assert (await reader.readline()).startswith(b"220")
    writer.write(b"EHLO again\r\n")  # plaintext instead of a ClientHello: handshake fails at once
    await writer.drain()
    assert await asyncio.wait_for(reader.read(), 5) == b""
    writer.close()
    for _ in range(40):
        if HandlerBase.global_sessions == 0:
            break
        await asyncio.sleep(0.05)
    assert HandlerBase.global_sessions == 0

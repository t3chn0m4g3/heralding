import asyncio
import base64
import smtplib

from heralding.capabilities import submission
from heralding.capabilities.handlerbase import HandlerBase
from heralding.tests.conftest import make_options


async def _server(serve, server_ssl_context):
    cap = submission.Submission(make_options(banner="Test", fqdn="mail.test.local"))
    cap.starttls_context = server_ssl_context
    return await serve(cap)


async def test_starttls_then_auth_plain_is_logged(
    serve, sink, server_ssl_context, client_ssl_context
):
    host, port = await _server(serve, server_ssl_context)

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


async def test_auth_before_starttls_is_also_logged(serve, sink, server_ssl_context):
    host, port = await _server(serve, server_ssl_context)

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


async def test_disconnect_after_starttls_cleans_up_session(serve, sink, server_ssl_context):
    host, port = await _server(serve, server_ssl_context)

    def run():
        client = smtplib.SMTP(host, port, local_hostname="localhost", timeout=5)
        try:
            client.ehlo("x")
            assert client.docmd("STARTTLS")[0] == 220
        finally:
            client.close()

    await asyncio.to_thread(run)
    await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert HandlerBase.global_sessions == 0

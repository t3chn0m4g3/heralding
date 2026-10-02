import asyncio
import base64
import http.client
import imaplib
import poplib
import smtplib

import pytest

from heralding.capabilities.handlerbase import HandlerBase
from heralding.tests.conftest import make_options


@pytest.mark.parametrize("name", ["https", "imaps", "pop3s", "smtps"])
async def test_implicit_tls_alias_logs_standard_client_login(
    name, serve, sink, server_ssl_context, client_ssl_context
):
    capability = HandlerBase.registry()[name](make_options(max_attempts=3))
    host, port = await serve(capability, server_ssl_context)

    def login():
        if name == "https":
            client = http.client.HTTPSConnection(host, port, context=client_ssl_context, timeout=5)
            try:
                token = base64.b64encode(b"tls-user:tls-password").decode()
                client.request("GET", "/", headers={"Authorization": "Basic " + token})
                response = client.getresponse()
                assert response.status == 401
                response.read()
            finally:
                client.close()
        elif name == "imaps":
            client = imaplib.IMAP4_SSL(host, port, ssl_context=client_ssl_context, timeout=5)
            try:
                with pytest.raises(imaplib.IMAP4.error, match="Authentication failed"):
                    client.login("tls-user", "tls-password")
            finally:
                client.logout()
        elif name == "pop3s":
            client = poplib.POP3_SSL(host, port, context=client_ssl_context, timeout=5)
            try:
                client.user("tls-user")
                with pytest.raises(poplib.error_proto):
                    client.pass_("tls-password")
            finally:
                client.quit()
        else:
            with smtplib.SMTP_SSL(
                host, port, local_hostname="localhost", context=client_ssl_context, timeout=5
            ) as client:
                client.ehlo()
                with pytest.raises(smtplib.SMTPAuthenticationError):
                    client.auth("PLAIN", lambda challenge=None: "\0tls-user\0tls-password")

    await asyncio.to_thread(login)
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["protocol"] == name
    assert (attempt["username"], attempt["password"]) == ("tls-user", "tls-password")

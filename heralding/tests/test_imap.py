import asyncio
import base64
import imaplib

import pytest

from heralding.capabilities.imap import Imap
from heralding.tests.conftest import make_options


def _options():
    return make_options(max_attempts=3, banner="* OK IMAP4rev1 Server Ready")


async def test_login(serve, sink):
    host, port = await serve(Imap(_options()))

    def run():
        client = imaplib.IMAP4(host, port)
        for user, password in [
            ("kajoj_admin", "thebestpassword"),
            ('"kajoj_admin"', "the best password"),
        ]:
            with pytest.raises(imaplib.IMAP4.error) as excinfo:
                client.login(user, password)
            assert excinfo.value.args[0] == "Authentication failed"
        client.logout()

    await asyncio.to_thread(run)
    attempts = await asyncio.to_thread(sink.wait_for_auth, 2)
    assert (attempts[0]["username"], attempts[0]["password"]) == ("kajoj_admin", "thebestpassword")
    assert (attempts[1]["username"], attempts[1]["password"]) == (
        "kajoj_admin",
        "the best password",
    )


async def test_authenticate_plain(serve, sink):
    host, port = await serve(Imap(_options()))

    def run():
        client = imaplib.IMAP4(host, port)
        for blob, expected in [
            ("\0kajoj_admin\0thebestpassword", "Authentication failed"),
            ("\0пайтон\0наилучшийпароль", "Authentication failed"),
            (
                "kajoj_admin\0the best password",
                "AUTHENTICATE command error: BAD [b'invalid command']",
            ),
        ]:
            with pytest.raises(imaplib.IMAP4.error) as excinfo:
                client.authenticate("PLAIN", lambda _x, blob=blob: blob)
            assert excinfo.value.args[0] == expected
        client.logout()

    await asyncio.to_thread(run)
    attempts = await asyncio.to_thread(sink.wait_for_auth, 2)
    assert attempts[1]["username"] == "пайтон"
    assert attempts[1]["password"] == "наилучшийпароль"


async def test_imap_allows_exactly_max_attempts(serve, sink):
    host, port = await serve(Imap(make_options(max_attempts=2, banner="* OK")))

    def run():
        client = imaplib.IMAP4(host, port, timeout=5)
        try:
            for _ in range(2):
                with pytest.raises(imaplib.IMAP4.error, match="Authentication failed"):
                    client.login("u", "p")
            with pytest.raises(imaplib.IMAP4.abort):
                client.noop()
        finally:
            client.shutdown()

    await asyncio.to_thread(run)
    assert len(await asyncio.to_thread(sink.wait_for_auth, 2)) == 2


async def test_imap_login_latin1_is_logged(serve, sink):
    host, port = await serve(Imap(make_options(max_attempts=3, banner="* OK")))

    def run():
        client = imaplib.IMAP4(host, port, timeout=5)
        client._encoding = "latin1"
        try:
            with pytest.raises(imaplib.IMAP4.error):
                client.login("u", "pä")
        finally:
            client.shutdown()

    await asyncio.to_thread(run)
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["password"] == "p\\xe4"


async def test_imap_authenticate_plain_sasl_ir(serve, sink):
    host, port = await serve(Imap(make_options(max_attempts=3, banner="* OK")))

    def run():
        client = imaplib.IMAP4(host, port, timeout=5)
        try:
            typ, _ = client._simple_command("AUTHENTICATE", "PLAIN", base64.b64encode(b"\0u\0p "))
            assert typ == "NO"
        finally:
            client.shutdown()

    await asyncio.to_thread(run)
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["password"] == "p "


async def test_imap_login_with_literals(serve, sink):
    host, port = await serve(Imap(make_options(max_attempts=3, banner="* OK")))

    def run():
        client = imaplib.IMAP4(host, port, timeout=5)
        try:
            client.literal = b'p"'
            typ, _ = client._simple_command("LOGIN", "u")
            assert typ == "NO"
        finally:
            client.shutdown()

    await asyncio.to_thread(run)
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("u", 'p"')

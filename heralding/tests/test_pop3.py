import asyncio
import poplib

import pytest

from heralding.capabilities.pop3 import Pop3
from heralding.tests.conftest import make_options


async def test_login(serve, sink):
    host, port = await serve(Pop3(make_options(max_attempts=3, banner="+OK POP3 server ready")))

    def run():
        client = poplib.POP3(host, port, timeout=5)
        try:
            assert client.getwelcome().startswith(b"+OK")
            assert client.user("wakkwakk") == b"+OK User accepted"
            with pytest.raises(poplib.error_proto, match="Authentication failed"):
                client.pass_("wakkwakk")
            with pytest.raises(poplib.error_proto, match="Unknown command"):
                client.retr(1)
        finally:
            client.close()
        client = poplib.POP3(host, port, timeout=5)
        try:
            with pytest.raises(poplib.error_proto, match="No username given"):
                client.pass_("bond")
        finally:
            client.close()

    await asyncio.to_thread(run)
    attempts = await asyncio.to_thread(sink.wait_for_auth, 1)
    assert (attempts[0]["username"], attempts[0]["password"]) == ("wakkwakk", "wakkwakk")


@pytest.mark.parametrize("noop", [False, True])
async def test_pop3_enforces_max_attempts_even_after_noop(serve, sink, noop):
    host, port = await serve(Pop3(make_options(max_attempts=2, banner="+OK")))

    def run():
        client = poplib.POP3(host, port, timeout=5)
        try:
            if noop:
                assert client.noop().startswith(b"+OK")
            for _ in range(2):
                client.user("u")
                with pytest.raises(poplib.error_proto, match="Authentication failed"):
                    client.pass_("p")
            with pytest.raises((poplib.error_proto, OSError)):
                client.noop()
        finally:
            client.close()

    await asyncio.to_thread(run)
    assert len(await asyncio.to_thread(sink.wait_for_auth, 2)) == 2


def test_pop3_max_attempts_is_per_instance():
    two = Pop3(make_options(max_attempts=2, banner="+OK"))
    five = Pop3(make_options(max_attempts=5, banner="+OK"))
    assert (two.max_tries, five.max_tries) == (2, 5)

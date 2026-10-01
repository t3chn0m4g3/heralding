import asyncio

from heralding.capabilities.pop3 import Pop3
from heralding.tests.conftest import make_options


async def test_login(serve, sink):
    cap = Pop3(make_options(max_attempts=3, banner="+OK POP3 server ready"))
    host, port = await serve(cap)

    sequences = [
        # invalid login, invalid password
        (
            ("USER wakkwakk", b"+OK User accepted"),
            ("PASS wakkwakk", b"-ERR Authentication failed."),
        ),
        # PASS without user
        (("PASS bond", b"-ERR No username given."),),
        # Try to run a TRANSACTION state command in AUTHORIZATION state
        (("RETR", b"-ERR Unknown command"),),
    ]
    for sequence in sequences:
        reader, writer = await asyncio.open_connection(host, port)
        banner = await reader.readline()
        assert banner.startswith(b"+OK")
        for command, expected in sequence:
            writer.write(command.encode() + b"\r\n")
            await writer.drain()
            response = await reader.readline()
            assert response.rstrip() == expected
        writer.close()

    attempts = await asyncio.to_thread(sink.wait_for_auth, 1)
    assert (attempts[0]["username"], attempts[0]["password"]) == ("wakkwakk", "wakkwakk")


async def test_pop3_enforces_max_attempts(serve, sink):
    cap = Pop3(make_options(max_attempts=2, banner="+OK"))
    host, port = await serve(cap)
    reader, writer = await asyncio.open_connection(host, port)
    await reader.readline()
    for _ in range(2):
        writer.write(b"USER u\r\n")
        await writer.drain()
        await reader.readline()
        writer.write(b"PASS p\r\n")
        await writer.drain()
        assert (await reader.readline()).startswith(b"-ERR")
    assert await asyncio.wait_for(reader.read(), 5) == b""
    writer.close()


async def test_pop3_max_attempts_is_per_instance(serve, sink):
    two = Pop3(make_options(max_attempts=2, banner="+OK"))
    five = Pop3(make_options(max_attempts=5, banner="+OK"))
    assert (two.max_tries, five.max_tries) == (2, 5)

import asyncio

import heralding.capabilities.socks5 as socks
from heralding.tests.conftest import make_options


async def test_socks_authentication(serve, sink):
    host, port = await serve(socks.Socks5(make_options()))
    reader, writer = await asyncio.open_connection(host, port)

    # Greeting: version + number of methods + methods
    writer.write(socks.SOCKS_VERSION + b"\x01" + socks.AUTH_METHOD)
    await writer.drain()
    assert await reader.readexactly(2) == socks.SOCKS_VERSION + socks.AUTH_METHOD

    # Sub-negotiation: version + ulen + username + plen + password
    writer.write(b"\x01\x08username\x08password")
    await writer.drain()
    # Current behaviour answers with the method byte; the RFC 1929 fix (0x01) lands in Task 15.
    assert await reader.readexactly(2) == socks.AUTH_METHOD + socks.SOCKS_FAIL
    writer.close()

    attempts = await asyncio.to_thread(sink.wait_for_auth, 1)
    assert (attempts[0]["username"], attempts[0]["password"]) == ("username", "password")

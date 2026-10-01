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
    # RFC 1929: sub-negotiation version 0x01 + status (0xff = failure)
    assert await reader.readexactly(2) == b"\x01\xff"
    writer.close()

    attempts = await asyncio.to_thread(sink.wait_for_auth, 1)
    assert (attempts[0]["username"], attempts[0]["password"]) == ("username", "password")


async def test_socks5_empty_password(serve, sink):
    host, port = await serve(socks.Socks5(make_options()))
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(b"\x05\x01\x02")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x02"
    writer.write(b"\x01\x04user\x00")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x01\xff"
    writer.close()
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("user", "")


async def test_socks5_credentials_split_across_packets(serve, sink):
    host, port = await serve(socks.Socks5(make_options()))
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(b"\x05\x01\x02")
    await writer.drain()
    await reader.readexactly(2)
    writer.write(b"\x01\x05ad")
    await writer.drain()
    await asyncio.sleep(0.1)
    writer.write(b"min\x06secret")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x01\xff"
    writer.close()
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("admin", "secret")

import asyncio

from heralding.capabilities import telnet
from heralding.tests.conftest import make_options

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240


async def _read_until(reader, writer, needle: bytes, timeout: float = 5.0) -> bytes:
    """Read until `needle` appears, answering telnet option negotiation with refusals."""
    data = bytearray()
    in_sub = False
    async with asyncio.timeout(timeout):
        while needle.lower() not in bytes(data).lower():
            chunk = await reader.read(256)
            if not chunk:
                break
            i = 0
            while i < len(chunk):
                b = chunk[i]
                if b == IAC and i + 1 < len(chunk):
                    cmd = chunk[i + 1]
                    if cmd in (DO, DONT, WILL, WONT) and i + 2 < len(chunk):
                        opt = chunk[i + 2]
                        writer.write(bytes([IAC, WONT if cmd in (DO, DONT) else DONT, opt]))
                        i += 3
                        continue
                    if cmd == SB:
                        in_sub = True
                    elif cmd == SE:
                        in_sub = False
                    i += 2
                    continue
                if not in_sub:
                    data.append(b)
                i += 1
            await writer.drain()
    return bytes(data)


async def test_invalid_login(serve, sink):
    cap = telnet.Telnet(make_options(max_attempts=3))
    host, port = await serve(cap)
    reader, writer = await asyncio.open_connection(host, port)

    prompt = await _read_until(reader, writer, b"Username: ")
    assert b"Username: " in prompt
    writer.write(b"someuser\r\n")
    await writer.drain()
    prompt = await _read_until(reader, writer, b"Password: ")
    assert prompt.endswith(b"Password: ")
    writer.write(b"somepass\r\n")
    await writer.drain()

    attempts = await asyncio.to_thread(sink.wait_for_auth, 1)
    assert (attempts[0]["username"], attempts[0]["password"]) == ("someuser", "somepass")
    writer.close()

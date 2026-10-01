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


async def test_overlong_line_is_truncated_not_fatal(serve, sink, caplog):
    import logging

    caplog.set_level(logging.WARNING)
    cap = telnet.Telnet(make_options(max_attempts=3))
    host, port = await serve(cap)
    reader, writer = await asyncio.open_connection(host, port)
    await _read_until(reader, writer, b"Username: ")
    writer.write(b"A" * 5000 + b"\r\n")
    await writer.drain()
    await _read_until(reader, writer, b"Password: ")
    writer.write(b"p\r\n")
    await writer.drain()
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert len(attempt["username"]) == 1024
    writer.close()
    await asyncio.sleep(0.3)
    # no asyncio "socket.send() raised exception." spam after the client is gone
    assert sum("socket.send()" in rec.getMessage() for rec in caplog.records) == 0


async def test_prompts_match_tpot_smoke(serve, sink):
    cap = telnet.Telnet(make_options(max_attempts=3))
    host, port = await serve(cap)
    reader, writer = await asyncio.open_connection(host, port)
    data = await _read_until(reader, writer, b"sername:")
    assert b"username:" in data.lower()
    writer.write(b"u\r\n")
    await writer.drain()
    data = await _read_until(reader, writer, b"assword:")
    assert b"password:" in data.lower()
    writer.close()


async def test_latin1_password_is_logged(serve, sink):
    cap = telnet.Telnet(make_options(max_attempts=3))
    host, port = await serve(cap)
    reader, writer = await asyncio.open_connection(host, port)
    await _read_until(reader, writer, b"Username: ")
    writer.write(b"u\r\n")
    await writer.drain()
    await _read_until(reader, writer, b"Password: ")
    writer.write(b"p\xe4\r\n")
    await writer.drain()
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["password"] == "p\\xe4"
    writer.close()


async def test_max_attempts_is_per_capability_instance(serve, sink):
    cap_two = telnet.Telnet(make_options(max_attempts=2))
    cap_five = telnet.Telnet(make_options(max_attempts=5))
    assert cap_two.max_tries == 2
    assert cap_five.max_tries == 5
    host, port = await serve(cap_two)
    reader, writer = await asyncio.open_connection(host, port)
    for i in range(2):
        await _read_until(reader, writer, b"Username: ")
        writer.write(f"u{i}\r\n".encode())
        await writer.drain()
        await _read_until(reader, writer, b"Password: ")
        writer.write(b"p\r\n")
        await writer.drain()
    # after max_attempts the server closes the connection
    tail = await asyncio.wait_for(reader.read(), 5)
    assert b"Username: " in tail  # the Hydra-friendly final prompt
    writer.close()
    assert len(await asyncio.to_thread(sink.wait_for_auth, 2)) == 2


async def test_client_disconnect_ends_session_promptly(serve, sink):
    from heralding.capabilities.handlerbase import HandlerBase

    cap = telnet.Telnet(make_options(max_attempts=3))
    host, port = await serve(cap)
    reader, writer = await asyncio.open_connection(host, port)
    await _read_until(reader, writer, b"Username: ")
    writer.write(b"u\r\n")
    await writer.drain()
    await _read_until(reader, writer, b"Password: ")
    writer.write(b"p\r\n")
    await writer.drain()
    await asyncio.to_thread(sink.wait_for_auth, 1)
    writer.close()
    await writer.wait_closed()
    for _ in range(40):  # must not wait for the 30 s session timeout
        if HandlerBase.global_sessions == 0:
            break
        await asyncio.sleep(0.05)
    assert HandlerBase.global_sessions == 0


async def test_disconnect_at_password_prompt_ends_session(serve, sink):
    from heralding.capabilities.handlerbase import HandlerBase

    cap = telnet.Telnet(make_options(max_attempts=3))
    host, port = await serve(cap)
    reader, writer = await asyncio.open_connection(host, port)
    await _read_until(reader, writer, b"Username: ")
    writer.write(b"u\r\n")
    await writer.drain()
    await _read_until(reader, writer, b"Password: ")
    writer.close()  # leave while the server waits for the password
    await writer.wait_closed()
    for _ in range(40):
        if HandlerBase.global_sessions == 0:
            break
        await asyncio.sleep(0.05)
    assert HandlerBase.global_sessions == 0

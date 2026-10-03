import asyncio

import telnetlib3

from heralding.capabilities import telnet
from heralding.tests.conftest import make_options


async def _read_until(reader, writer, needle: bytes, timeout: float = 5.0) -> bytes:
    data = bytearray()
    async with asyncio.timeout(timeout):
        while needle.lower() not in bytes(data).lower():
            chunk = await reader.read(256)
            if not chunk:
                break
            data.extend(chunk)
    return bytes(data)


async def _connect(host, port):
    return await telnetlib3.open_connection(
        host, port, encoding=False, connect_minwait=0.01, connect_maxwait=0.05
    )


async def test_invalid_login(serve, sink):
    cap = telnet.Telnet(make_options(max_attempts=3))
    host, port = await serve(cap)
    reader, writer = await _connect(host, port)

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
    reader, writer = await _connect(host, port)
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


async def test_default_login_prompts(serve, sink):
    cap = telnet.Telnet(make_options(max_attempts=3))
    host, port = await serve(cap)
    reader, writer = await _connect(host, port)
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
    reader, writer = await _connect(host, port)
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
    reader, writer = await _connect(host, port)
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
    reader, writer = await _connect(host, port)
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
    reader, writer = await _connect(host, port)
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


async def test_terminal_type_environment_and_window_size_are_recorded(serve, sink):
    cap = telnet.Telnet(make_options(max_attempts=1))
    host, port = await serve(cap)
    reader, writer = await telnetlib3.open_connection(
        host,
        port,
        encoding=False,
        term="xterm-256color",
        cols=132,
        rows=43,
        connect_minwait=0.2,
        connect_maxwait=1.0,
    )
    await _read_until(reader, writer, b"Username: ")
    writer.write(b"root\r\n")
    await writer.drain()
    await _read_until(reader, writer, b"Password: ")
    writer.write(b"toor\r\n")
    await writer.drain()
    ended = (await asyncio.to_thread(sink.wait_for_session_end, 1))[0]
    writer.close()
    aux = ended["auxiliary_data"]
    assert aux["terminal_type"].lower() == "xterm-256color"
    assert aux["window_size"] == "132x43"
    assert aux["environment"].get("TERM", "").lower() == "xterm-256color"


def test_option_value_is_requested_once():
    from heralding.libs.telnetsrv import telnetsrvlib as lib

    class Writer:
        def __init__(self):
            self.chunks = []

        def write(self, data):
            self.chunks.append(data)

        def get_extra_info(self, name):
            return ("127.0.0.1", 2323)

    writer = Writer()
    handler = lib.TelnetHandlerBase(None, writer, ("127.0.0.1", 40000))
    for _ in range(100):  # a client repeating WILL must not grow the output
        handler._option_received(lib.WILL, lib.TTYPE)
        handler._option_received(lib.WILL, lib.NEW_ENVIRON)
    assert len(writer.chunks) == 2

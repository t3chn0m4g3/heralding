import asyncio

from heralding.capabilities import ftp, imap, pop3, telnet
from heralding.tests.conftest import make_options
from heralding.tests.test_telnet import _read_until


async def _lines(host, port, lines, skip_banner=True):
    reader, writer = await asyncio.open_connection(host, port)
    if skip_banner:
        await reader.readline()
    for line in lines:
        writer.write(line)
        await writer.drain()
        await reader.readline()
    writer.close()
    await writer.wait_closed()


async def test_pop3_commands_are_recorded(serve, sink):
    host, port = await serve(pop3.Pop3(make_options(max_attempts=3, banner="+OK")))
    await _lines(host, port, [b"CAPA\r\n", b"USER a\r\n", b"PASS b\r\n", b"QUIT\r\n"])
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert ended[0]["auxiliary_data"]["commands"] == ["CAPA", "USER a", "PASS b", "QUIT"]
    assert "commands_truncated" not in ended[0]["auxiliary_data"]


async def test_command_list_is_bounded(serve, sink):
    host, port = await serve(pop3.Pop3(make_options(max_attempts=99, banner="+OK")))
    lines = [f"NOOP {'x' * 300} {i}\r\n".encode() for i in range(80)] + [b"QUIT\r\n"]
    await _lines(host, port, lines)
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    aux = ended[0]["auxiliary_data"]
    assert len(aux["commands"]) == 50
    assert all(len(c) <= 256 for c in aux["commands"])
    assert aux["commands_truncated"] is True


async def test_ftp_commands_and_latin1(serve, sink):
    host, port = await serve(ftp.ftp(make_options(max_attempts=3, banner="b", syst_type="UNIX")))
    await _lines(host, port, [b"SYST\r\n", b"USER u\r\n", b"PASS p\xe4\r\n", b"QUIT\r\n"])
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert ended[0]["auxiliary_data"]["commands"] == ["SYST", "USER u", "PASS p\\xe4", "QUIT"]


async def test_imap_commands_are_recorded(serve, sink):
    host, port = await serve(imap.Imap(make_options(max_attempts=3, banner="* OK")))
    reader, writer = await asyncio.open_connection(host, port)
    await reader.readline()
    writer.write(b"a1 CAPABILITY\r\n")
    await writer.drain()
    await reader.readline()
    await reader.readline()
    writer.write(b"a2 LOGIN u p\r\na3 LOGOUT\r\n")
    await writer.drain()
    await asyncio.wait_for(reader.read(), 5)
    writer.close()
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert ended[0]["auxiliary_data"]["commands"] == ["a1 CAPABILITY", "a2 LOGIN u p", "a3 LOGOUT"]


async def test_telnet_input_lines_are_recorded(serve, sink):
    host, port = await serve(telnet.Telnet(make_options(max_attempts=1)))
    reader, writer = await asyncio.open_connection(host, port)
    await _read_until(reader, writer, b"Username: ")
    writer.write(b"root\r\n")
    await writer.drain()
    await _read_until(reader, writer, b"Password: ")
    writer.write(b"toor\r\n")
    await writer.drain()
    await asyncio.wait_for(reader.read(), 5)
    writer.close()
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert ended[0]["auxiliary_data"]["commands"] == ["root", "toor"]


async def test_pop3_latin1_password_is_logged(serve, sink):
    host, port = await serve(pop3.Pop3(make_options(max_attempts=3, banner="+OK")))
    await _lines(host, port, [b"USER u\r\n", b"PASS p\xe4\r\n"])
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["password"] == "p\\xe4"

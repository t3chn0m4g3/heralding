import asyncio
import ftplib
import imaplib
import poplib

import pytest

from heralding.capabilities import ftp, imap, pop3, telnet
from heralding.tests.conftest import make_options
from heralding.tests.test_telnet import _connect, _read_until


async def test_pop3_commands_are_recorded(serve, sink):
    host, port = await serve(pop3.Pop3(make_options(max_attempts=3, banner="+OK")))

    def run():
        client = poplib.POP3(host, port, timeout=5)
        try:
            with pytest.raises(poplib.error_proto):
                client.capa()
            client.user("a")
            with pytest.raises(poplib.error_proto):
                client.pass_("b")
            client.quit()
        finally:
            client.close()

    await asyncio.to_thread(run)
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert ended[0]["auxiliary_data"]["commands"] == ["CAPA", "USER a", "PASS b", "QUIT"]
    assert "commands_truncated" not in ended[0]["auxiliary_data"]


async def test_command_list_is_bounded(serve, sink):
    host, port = await serve(pop3.Pop3(make_options(max_attempts=99, banner="+OK")))

    def run():
        client = poplib.POP3(host, port, timeout=5)
        try:
            for i in range(80):
                client._shortcmd("NOOP " + "x" * 300 + f" {i}")
            client.quit()
        finally:
            client.close()

    await asyncio.to_thread(run)
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    aux = ended[0]["auxiliary_data"]
    assert len(aux["commands"]) == 50
    assert all(len(c) <= 256 for c in aux["commands"])
    assert aux["commands_truncated"] is True


async def test_ftp_commands_and_latin1(serve, sink):
    host, port = await serve(ftp.ftp(make_options(max_attempts=3, banner="b", syst_type="UNIX")))

    def run():
        with ftplib.FTP(encoding="latin1") as client:
            client.connect(host, port, timeout=5)
            client.sendcmd("SYST")
            with pytest.raises(ftplib.error_perm):
                client.login("u", "pä")

    await asyncio.to_thread(run)
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert ended[0]["auxiliary_data"]["commands"] == ["SYST", "USER u", "PASS p\\xe4", "QUIT"]


async def test_imap_commands_are_recorded(serve, sink):
    host, port = await serve(imap.Imap(make_options(max_attempts=3, banner="* OK")))

    def run():
        client = imaplib.IMAP4(host, port, timeout=5)
        with pytest.raises(imaplib.IMAP4.error):
            client.login("u", "p")
        client.logout()

    await asyncio.to_thread(run)
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    commands = [line.split(" ", 1)[1] for line in ended[0]["auxiliary_data"]["commands"]]
    assert commands == ["CAPABILITY", 'LOGIN u "p"', "LOGOUT"]


async def test_telnet_input_lines_are_recorded(serve, sink):
    host, port = await serve(telnet.Telnet(make_options(max_attempts=1)))
    reader, writer = await _connect(host, port)
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

    def run():
        client = poplib.POP3(host, port, timeout=5)
        client.encoding = "latin1"
        try:
            client.user("u")
            with pytest.raises(poplib.error_proto):
                client.pass_("pä")
        finally:
            client.close()

    await asyncio.to_thread(run)
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["password"] == "p\\xe4"

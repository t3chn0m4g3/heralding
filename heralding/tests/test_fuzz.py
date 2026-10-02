"""Garbage input against every plain-TCP capability: no leak, no traceback, server stays up."""

import asyncio
import logging
import random

import pytest

import heralding.capabilities  # noqa: F401
from heralding.capabilities.handlerbase import HandlerBase
from heralding.tests.conftest import make_options

FORBIDDEN = (
    "Traceback",
    "RuntimeError",
    "ModuleNotFoundError",
    "OSError:",
    "Exception in callback",
    "Unhandled exception",
)
PSD = {
    "ftp": dict(max_attempts=3, banner="b", syst_type="UNIX"),
    "telnet": dict(max_attempts=3),
    "pop3": dict(max_attempts=3, banner="+OK"),
    "imap": dict(max_attempts=3, banner="* OK"),
    "http": dict(banner=""),
    "smtp": dict(banner="b", fqdn="h"),
    "submission": dict(banner="b", fqdn="h"),
    "http_proxy": dict(banner=""),
    "rdp": dict(
        banner="",
        cert={
            "common_name": "*",
            "country": "US",
            "state": "None",
            "locality": "None",
            "organization": "None",
            "organizational_unit": "None",
            "valid_days": 365,
            "serial_number": 0,
        },
    ),
}
PLAIN_TCP = [
    "ftp",
    "telnet",
    "pop3",
    "imap",
    "http",
    "smtp",
    "vnc",
    "socks5",
    "mysql",
    "postgresql",
    "rdp",
    # milestone C
    "redis",
    "mqtt",
    "http_proxy",
    "submission",
    "ldap",
    "mssql",
    "sip",
]


def _payloads():
    rnd = random.Random(1234)
    yield b""
    yield b"\xff" * 10
    yield rnd.randbytes(2000)
    yield b"A" * 70000 + b"\r\n"
    yield b"USER \x00\xff\xfe\r\nPASS \x80\r\n"
    yield b"GET / HTTP/1.1\r\n" + b"X: y\r\n" * 200 + b"\r\n"


async def _wait_sessions_zero():
    for _ in range(100):
        if HandlerBase.global_sessions == 0:
            return
        await asyncio.sleep(0.05)


@pytest.mark.parametrize("name", PLAIN_TCP)
async def test_garbage_does_not_leak_or_trace(name, serve, sink, caplog, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # rdp.pem / ssh.key land here
    caplog.set_level(logging.DEBUG)
    cls = HandlerBase.registry()[name]
    cap = cls(make_options(timeout=2, **PSD.get(name, {})))
    host, port = await serve(cap)
    for payload in _payloads():
        r, w = await asyncio.open_connection(host, port)
        w.write(payload)
        try:
            await w.drain()
            await asyncio.wait_for(r.read(4096), 1)
        except TimeoutError, ConnectionError:
            pass
        w.close()
    # abrupt close mid-handshake
    r, w = await asyncio.open_connection(host, port)
    w.transport.abort()
    await _wait_sessions_zero()
    assert HandlerBase.global_sessions == 0
    text = "\n".join(
        f"{rec.levelname} {rec.getMessage()}"
        for rec in caplog.records
        if rec.levelno >= logging.INFO
    )
    for bad in FORBIDDEN:
        assert bad not in text, text
    # server still alive
    r, w = await asyncio.open_connection(host, port)
    w.close()

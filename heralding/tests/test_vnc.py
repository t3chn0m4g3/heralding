import asyncio
import os

import heralding.honeypot
from heralding.capabilities.handlerbase import HandlerBase
from heralding.capabilities.vnc import AUTH_FAILED, AUTH_METHODS, RFB_VERSION, VNC_AUTH, Vnc
from heralding.tests.conftest import make_options


async def _handshake(host, port):
    reader, writer = await asyncio.open_connection(host, port)
    assert await reader.readexactly(len(RFB_VERSION)) == RFB_VERSION
    writer.write(RFB_VERSION)
    await writer.drain()
    assert await reader.readexactly(len(AUTH_METHODS)) == AUTH_METHODS
    writer.write(VNC_AUTH)
    await writer.drain()
    challenge = await reader.readexactly(16)
    return reader, writer, challenge


async def test_vnc_authentication(serve, sink):
    host, port = await serve(Vnc(make_options()))
    reader, writer, challenge = await _handshake(host, port)
    assert len(challenge) == 16
    # Pretend we encrypted the challenge with DES.
    writer.write(os.urandom(16))
    await writer.drain()
    assert await reader.readexactly(4) == AUTH_FAILED
    writer.close()

    attempts = await asyncio.to_thread(sink.wait_for_auth, 1)
    assert attempts[0]["protocol"] == "vnc"
    assert attempts[0]["password_hash"] is not None


async def test_vnc_hash_format_and_crack(serve, sink, monkeypatch):
    from Crypto.Cipher import DES

    from heralding.libs.cracker.vnc import get_vnc_key

    monkeypatch.setattr(heralding.honeypot.Honeypot, "wordlist", ["wrong", "secret"])
    host, port = await serve(Vnc(make_options()))
    reader, writer, challenge = await _handshake(host, port)
    response = DES.new(get_vnc_key(b"secret"), DES.MODE_ECB).encrypt(challenge)
    writer.write(response)
    await writer.drain()
    assert await reader.readexactly(4) == AUTH_FAILED
    writer.close()

    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["password"] == "secret"
    assert attempt["password_hash"] == f"$vnc$*{challenge.hex().upper()}*{response.hex().upper()}"


async def test_vnc_non_ascii_wordlist_entry_is_tolerated(serve, sink, monkeypatch):
    monkeypatch.setattr(heralding.honeypot.Honeypot, "wordlist", ["pässwörd", "ünïcode"])
    host, port = await serve(Vnc(make_options()))
    reader, writer, _ = await _handshake(host, port)
    writer.write(os.urandom(16))
    await writer.drain()
    assert await reader.readexactly(4) == AUTH_FAILED
    writer.close()
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["password"] is None
    assert attempt["password_hash"].startswith("$vnc$*")


async def test_vnc_short_response_is_not_fatal(serve, sink):
    host, port = await serve(Vnc(make_options(timeout=2)))
    reader, writer, _ = await _handshake(host, port)
    writer.write(b"\x00" * 5)
    await writer.drain()
    writer.close()
    for _ in range(60):
        if HandlerBase.global_sessions == 0:
            break
        await asyncio.sleep(0.05)
    assert HandlerBase.global_sessions == 0


def test_crack_semaphore_is_per_instance():
    a, b = Vnc(make_options()), Vnc(make_options())
    assert a._semaphore() is not b._semaphore()

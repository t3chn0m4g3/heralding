import asyncio
import os

from heralding.capabilities.vnc import AUTH_FAILED, AUTH_METHODS, RFB_VERSION, VNC_AUTH, Vnc
from heralding.tests.conftest import make_options


async def test_vnc_authentication(serve, sink):
    host, port = await serve(Vnc(make_options()))
    reader, writer = await asyncio.open_connection(host, port)

    assert await reader.readexactly(len(RFB_VERSION)) == RFB_VERSION
    writer.write(RFB_VERSION)
    await writer.drain()

    assert await reader.readexactly(len(AUTH_METHODS)) == AUTH_METHODS
    writer.write(VNC_AUTH)
    await writer.drain()

    challenge = await reader.readexactly(16)
    assert len(challenge) == 16
    # Pretend we encrypted the challenge with DES.
    writer.write(os.urandom(16))
    await writer.drain()

    assert await reader.readexactly(4) == AUTH_FAILED
    writer.close()

    attempts = await asyncio.to_thread(sink.wait_for_auth, 1)
    assert attempts[0]["protocol"] == "vnc"
    assert attempts[0]["password_hash"] is not None

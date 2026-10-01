import asyncio

import pytest

from heralding.capabilities import rdp
from heralding.tests.conftest import make_options

# x224 Connection Request with RDP negotiation request (TLS)
CONNECTION_REQUEST = b"\x03\x00\x00)$\xe0\x00\x00\x00\x00\x00Cookie: mstshash=xyz\r\n\x01\x00\x08\x00\x01\x00\x00\x00"


def _rdp_options():
    return make_options(
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
    )


async def test_connection_request_is_confirmed(serve, sink, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cap = rdp.RDP(_rdp_options())
    host, port = await serve(cap)
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(CONNECTION_REQUEST)
    await writer.drain()
    tpkt = await asyncio.wait_for(reader.readexactly(4), 5)
    assert tpkt[:2] == b"\x03\x00"
    length = int.from_bytes(tpkt[2:4], "big")
    body = await asyncio.wait_for(reader.readexactly(length - 4), 5)
    # x224 Connection Confirm (0xD0) followed by RDP_NEG_RSP (type 0x02)
    assert body[1] == 0xD0
    assert body[7] == 0x02
    writer.close()


@pytest.mark.skip(reason="RDP TLS handshake is repaired in P7 (issue #152)")
async def test_credentials_are_logged_over_tls(serve, sink):
    pass

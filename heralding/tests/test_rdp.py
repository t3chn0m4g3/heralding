import asyncio
import socket
import ssl
import warnings

import pytest

from heralding.capabilities import rdp
from heralding.capabilities.handlerbase import HandlerBase
from heralding.tests.conftest import make_options

# x224 Connection Request with RDP negotiation request (TLS)
CONNECTION_REQUEST = b"\x03\x00\x00)$\xe0\x00\x00\x00\x00\x00Cookie: mstshash=xyz\r\n\x01\x00\x08\x00\x01\x00\x00\x00"


def _rdp_options(**extra):
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
        **extra,
    )


class RDPClient:
    @classmethod
    def ConnectionRequestPDU(cls):
        # selects tls security as highest supported method
        return b"\x03\x00\x00)$\xe0\x00\x00\x00\x00\x00Cookie: mstshash=xyz\r\n\x01\x00\x08\x00\x01\x00\x00\x00"

    @classmethod
    def ClientDataPDU(cls):
        tpkt = b"\x03\x00\x01\x8b"
        cc_header = b"\x02\xf0\x80"
        data = b'\x7fe\x82\x01\x7f\x04\x01\x01\x04\x01\x01\x01\x01\xff0\x1a\x02\x01"\x02\x01\x02\x02\x01\x00\x02\x01\x01\x02\x01\x00\x02\x01\x01\x02\x03\x00\xff\xff\x02\x01\x020\x19\x02\x01\x01\x02\x01\x01\x02\x01\x01\x02\x01\x01\x02\x01\x00\x02\x01\x01\x02\x02\x04 \x02\x01\x020 \x02\x03\x00\xff\xff\x02\x03\x00\xfc\x17\x02\x03\x00\xff\xff\x02\x01\x01\x02\x01\x00\x02\x01\x01\x02\x03\x00\xff\xff\x02\x01\x02\x04\x82\x01\x19\x00\x05\x00\x14|\x00\x01\x81\x10\x00\x08\x00\x10\x00\x01\xc0\x00Duca\x81\x02\x01\xc0\xea\x00\x04\x00\x08\x00\x00\x04\x00\x03\x01\xca\x03\xaa\t\x04\x00\x00(\n\x00\x00p\x00o\x00p\x00-\x00o\x00s\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xca\x01\x00\x00\x00\x00\x00\x10\x00\x07\x00!\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\xc0\x0c\x00\r\x00\x00\x00\x00\x00\x00\x00\x02\xc0\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        return tpkt + cc_header + data

    @classmethod
    def ErectDomainRequest(cls):
        tpkt = b"\x03\x00\x00\x0c"
        cc_header = b"\x02\xf0\x80"
        data = b"\x04\x01\x00\x01\x00"
        return tpkt + cc_header + data

    @classmethod
    def AttactUserRequest(cls):
        tpkt = b"\x03\x00\x00\x08"
        cc_header = b"\x02\xf0\x80"
        data = b"\x28"
        return tpkt + cc_header + data

    @classmethod
    def ChannelJoinRequest(cls, channel):
        tpkt = b"\x03\x00\x00\x0c"
        cc_header = b"\x02\xf0\x80"
        if channel == 1007:
            data = b"8\x00\x06\x03\xef"
        if channel == 1003:
            data = b"8\x00\x06\x03\xeb"
        return tpkt + cc_header + data

    @classmethod
    def ClientInfoPDU(cls):
        # This conatins credentials
        tpkt = b"\x03\x00\x01\x5f"
        cc_header = b"\x02\xf0\x80"
        data = b"d\x00\x06\x03\xebp\x81P@\x00\x00\x00\x00\x00\x00\x00\xfb\x07\t\x00\x02\x00\x08\x00\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00x\x00x\x00\x00\x00\x00\x00m\x00y\x00p\x00a\x00s\x00s\x001\x002\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x16\x001\x002\x007\x00.\x000\x00.\x000\x00.\x001\x00\x00\x00\x00\x00B\x00C\x00:\x00\\\x00W\x00i\x00n\x00d\x00o\x00w\x00s\x00\\\x00S\x00y\x00s\x00t\x00e\x00m\x003\x002\x00\\\x00m\x00s\x00t\x00s\x00c\x00a\x00x\x00.\x00d\x00l\x00l\x00\x00\x00\x00\x00\xb6\xfe\xff\xffC\x00\x00\x00l\x00\x00\x00i\x00\x00\x00e\x00\x00\x00n\x00\x00\x00t\x00\x00\x00 \x00\x00\x00L\x00\x00\x00o\x00\x00\x00c\x00\x00\x00a\x00\x00\x00l\x00\x00\x00 \x00\x00\x00T\x00\x00\x00i\x00\x00\x00m\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00C\x00\x00\x00l\x00\x00\x00i\x00\x00\x00e\x00\x00\x00n\x00\x00\x00t\x00\x00\x00 \x00\x00\x00L\x00\x00\x00o\x00\x00\x00c\x00\x00\x00a\x00\x00\x00l\x00\x00\x00 \x00\x00\x00T\x00\x00\x00i\x00\x00\x00m\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00"
        return tpkt + cc_header + data


async def test_connection_request_is_confirmed(serve, sink, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    host, port = await serve(rdp.RDP(_rdp_options()))
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(CONNECTION_REQUEST)
    await writer.drain()
    tpkt = await asyncio.wait_for(reader.readexactly(4), 5)
    assert tpkt[:2] == b"\x03\x00"
    length = int.from_bytes(tpkt[2:4], "big")
    body = await asyncio.wait_for(reader.readexactly(length - 4), 5)
    assert body[1] == 0xD0  # x224 Connection Confirm
    assert body[7] == 0x02  # RDP_NEG_RSP
    writer.close()


def _rdp_login(host, port, tls_version):
    s = socket.create_connection((host, port), 5)
    s.settimeout(5)
    s.sendall(RDPClient.ConnectionRequestPDU())
    s.recv(1024)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False  # the honeypot presents a self-signed certificate
    ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)  # TLSv1 on purpose
        ctx.minimum_version = ctx.maximum_version = getattr(ssl.TLSVersion, tls_version)
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    tls = ctx.wrap_socket(s)
    version = tls.version()  # negotiated now; None once the connection is closed
    tls.sendall(RDPClient.ClientDataPDU())
    tls.recv(4096)
    tls.sendall(RDPClient.ErectDomainRequest())
    tls.sendall(RDPClient.AttactUserRequest())
    tls.recv(512)
    tls.sendall(RDPClient.ChannelJoinRequest(1007))
    tls.recv(1024)
    tls.sendall(RDPClient.ChannelJoinRequest(1003))
    tls.recv(1024)
    tls.sendall(RDPClient.ClientInfoPDU())
    try:
        tls.recv(512)
    except ssl.SSLError, OSError:
        pass
    tls.close()
    return version


@pytest.mark.parametrize("tls_version", ["TLSv1_2", "TLSv1_3", "TLSv1"])
async def test_rdp_credentials_over_tls(serve, sink, tmp_path, monkeypatch, tls_version):
    if tls_version == "TLSv1" and not getattr(ssl, "HAS_TLSv1", False):
        pytest.skip("OpenSSL built without TLS 1.0")
    monkeypatch.chdir(tmp_path)
    host, port = await serve(rdp.RDP(_rdp_options()))
    try:
        negotiated = await asyncio.to_thread(_rdp_login, host, port, tls_version)
    except ssl.SSLError as exc:
        if tls_version == "TLSv1":
            pytest.skip(f"client side cannot do TLS 1.0 here: {exc}")
        raise
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("xxx", "mypass12")
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    aux = ended[0]["auxiliary_data"]
    assert aux["tls_version"] == negotiated
    assert aux["domain"] == ""


async def test_rdp_security_only_client_gets_negofail(serve, sink, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    host, port = await serve(rdp.RDP(_rdp_options(timeout=2)))
    reader, writer = await asyncio.open_connection(host, port)
    # x224 CR with RDP_NEG_REQ requesting PROTOCOL_RDP (0) only
    writer.write(b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\x00")
    await writer.drain()
    resp = await asyncio.wait_for(reader.read(), 5)
    assert resp[11] == 0x03  # RDP_NEG_FAILURE
    writer.close()
    for _ in range(40):
        if HandlerBase.global_sessions == 0:
            break
        await asyncio.sleep(0.05)
    assert HandlerBase.global_sessions == 0


def test_server_random_is_random_and_key_is_lazy():
    from heralding.libs.msrdp import security

    a, b = security.ServerSecurity(), security.ServerSecurity()
    assert a.server_random != b.server_random and len(a.server_random) == 32
    assert security.getRSAKeys() is security.getRSAKeys()  # cached, created on first use

"""CredSSP credential capture using the standard pyspnego client."""

import asyncio
import socket
from unittest.mock import AsyncMock

import pytest
import spnego

from heralding.libs.msrdp import credssp
from heralding.libs.msrdp.pdu import x224ConnectionConfirmPDU
from heralding.libs.msrdp.tls import TLS
from heralding.misc.session import Session


@pytest.mark.parametrize("version", [2, 6, 7])
async def test_credssp_request_versions_use_client_library(version):
    from spnego._credssp_structures import NegoData, TSRequest

    stream = bytearray(TSRequest(version, nego_tokens=[NegoData(b"token")]).pack())

    async def read(size):
        data = bytes(stream[:size])
        del stream[:size]
        return data

    parsed_version, token = await credssp.read_request(AsyncMock(read_tls=read))
    assert parsed_version == min(version, 6) and token == b"token"
    assert not stream


@pytest.mark.parametrize("kind", ["oversized", "missing_token", "invalid_version"])
async def test_credssp_rejects_invalid_library_generated_requests(kind):
    from spnego._credssp_structures import NegoData, TSRequest

    data = TSRequest(
        1 if kind == "invalid_version" else 6,
        nego_tokens=None
        if kind == "missing_token"
        else [NegoData(b"x" * (65537 if kind == "oversized" else 1))],
    ).pack()
    stream = bytearray(data)

    async def read(size):
        chunk = bytes(stream[:size])
        del stream[:size]
        return chunk

    with pytest.raises(ValueError):
        await credssp.read_request(AsyncMock(read_tls=read))
    if kind == "oversized":
        assert len(stream) > 65536  # rejected after the header, before reading the body


@pytest.mark.parametrize("offered,selected", [(1, 1), (2, 2), (3, 2), (11, 2)])
def test_rdp_security_selection(offered, selected):
    confirmation = x224ConnectionConfirmPDU(offered)
    confirmation.generate()
    assert confirmation.selected_protocol == selected
    assert not confirmation.sentNegoFail


@pytest.mark.parametrize("wrapped", [False, True])
async def test_credssp_ntlm_capture_and_explicit_login_failure(sink, server_ssl_context, wrapped):
    done = asyncio.get_running_loop().create_future()

    async def handler(reader, writer):
        session = Session("127.0.0.1", 40000, "rdp", {}, 3389, "127.0.0.1")
        try:
            tls = TLS(writer, reader, context=server_ssl_context)
            await tls.do_tls_handshake()
            await credssp.capture(tls, session)
            done.set_result(None)
        except Exception as exc:
            done.set_exception(exc)
        finally:
            session.end_session()
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    def login():
        negotiate = spnego.client(
            "CORP\\nla-user",
            "test-password",
            protocol="negotiate" if wrapped else "ntlm",
            options=spnego.NegotiateOptions.use_negotiate
            if wrapped
            else spnego.NegotiateOptions.use_ntlm,
        )
        client = spnego.client(
            "CORP\\nla-user",
            "test-password",
            protocol="credssp",
            credssp_negotiate_context=negotiate,
        )
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            token = client.step()
            with pytest.raises(spnego.exceptions.SpnegoError, match="(?i)status|logon|credential"):
                for _ in range(12):
                    if token:
                        sock.sendall(token)
                    received = sock.recv(65536)
                    assert received, "server closed without sending CredSSP logon failure"
                    token = client.step(received)
            assert not client.complete

    try:
        await asyncio.to_thread(login)
        await asyncio.wait_for(done, 5)
        auth = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
        assert auth["username"] == "CORP\\nla-user"
        assert auth["password"] is None
        assert auth["password_hash"].startswith("nla-user::CORP:")
    finally:
        server.close()
        await server.wait_closed()

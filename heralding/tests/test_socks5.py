import asyncio

import pytest

import heralding.capabilities.socks5 as socks
from heralding.tests.conftest import make_options


def _socks_connect(host, port, username, password):
    from python_socks import ProxyError, ProxyType
    from python_socks.sync import Proxy

    proxy = Proxy.create(ProxyType.SOCKS5, host, port, username=username, password=password)
    try:
        proxy.connect(dest_host="example.org", dest_port=80, timeout=5)
    except ProxyError as exc:
        return str(exc)
    return None


@pytest.mark.parametrize("password", ["proxypass"])
async def test_socks5_credentials_are_logged_with_standard_client(serve, sink, password):
    host, port = await serve(socks.Socks5(make_options()))
    error = await asyncio.to_thread(_socks_connect, host, port, "proxyuser", password)
    assert error is not None  # authentication refused, nothing forwarded
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("proxyuser", password)
    assert attempt["protocol"] == "socks5"
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert "USERNAME/PASSWORD" in ended[0]["auxiliary_data"]["client_auth_methods"]


@pytest.mark.parametrize("password", ["", "secret"])
async def test_library_auth_with_empty_password_and_fragmented_transport(serve, sink, password):
    import socket

    from python_socks._protocols.socks5 import (
        AuthMethodsRequest,
        AuthRequest,
        Connection,
        ReplyError,
    )

    host, port = await serve(socks.Socks5(make_options()))

    def run():
        protocol = Connection()
        with socket.create_connection((host, port), timeout=5) as stream:
            # The client's protocol API builds and parses messages. Only the transport
            # fragments them; no protocol fields are assembled in the test.
            def send(request):
                for byte in protocol.send(request):
                    stream.sendall(bytes([byte]))

            def receive():
                data = bytearray()
                while len(data) < 2:
                    chunk = stream.recv(2 - len(data))
                    if not chunk:
                        raise EOFError
                    data.extend(chunk)
                return protocol.receive(bytes(data))

            send(AuthMethodsRequest("proxyuser", "advertise-password-auth"))
            receive()
            send(AuthRequest("proxyuser", password))
            with pytest.raises(ReplyError, match="authentication failure"):
                receive()

    await asyncio.to_thread(run)
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("proxyuser", password)

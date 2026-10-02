import asyncio

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


async def test_socks5_credentials_are_logged_with_standard_client(serve, sink):
    host, port = await serve(socks.Socks5(make_options()))
    error = await asyncio.to_thread(_socks_connect, host, port, "proxyuser", "proxypass")
    assert error is not None  # authentication refused, nothing forwarded
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("proxyuser", "proxypass")
    assert attempt["protocol"] == "socks5"
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert "USERNAME/PASSWORD" in ended[0]["auxiliary_data"]["client_auth_methods"]

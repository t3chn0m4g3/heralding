import asyncio
import base64
import http.client as httpclient

import pytest

from heralding.capabilities import http_proxy
from heralding.tests.conftest import make_options


def _request(host, port, method, url, headers=None):
    client = httpclient.HTTPConnection(host, port, timeout=5)
    client.request(method, url, headers=headers or {})
    response = client.getresponse()
    body = response.read()
    client.close()
    return response.status, dict(response.getheaders()), body


async def test_absolute_uri_without_auth_gets_407(serve, sink):
    host, port = await serve(http_proxy.HttpProxy(make_options()))
    status, headers, _ = await asyncio.to_thread(
        _request, host, port, "GET", "http://example.org/index.html", {"Host": "example.org"}
    )
    assert status == 407
    assert headers["Proxy-Authenticate"].startswith("Basic")
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert ended[0]["auxiliary_data"]["target"] == "http://example.org/index.html"


async def test_proxy_credentials_are_logged(serve, sink):
    host, port = await serve(http_proxy.HttpProxy(make_options()))
    token = base64.b64encode(b"proxyuser:proxypass").decode()
    status, _, body = await asyncio.to_thread(
        _request,
        host,
        port,
        "GET",
        "http://example.org/",
        {"Host": "example.org", "Proxy-Authorization": "Basic " + token},
    )
    assert status == 407
    assert token.encode() not in body
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("proxyuser", "proxypass")
    assert attempt["protocol"] == "http_proxy"


async def test_connect_method_is_refused_not_forwarded(serve, sink):
    host, port = await serve(http_proxy.HttpProxy(make_options()))

    def run():
        client = httpclient.HTTPConnection(host, port, timeout=5)
        token = base64.b64encode(b"u:p").decode()
        client.set_tunnel("example.org", 443, headers={"Proxy-Authorization": "Basic " + token})
        try:
            with pytest.raises(OSError, match="407"):
                client.connect()
        finally:
            client.close()

    await asyncio.to_thread(run)
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("u", "p")
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert ended[0]["auxiliary_data"]["target"] == "example.org:443"
    assert ended[0]["auxiliary_data"]["method"] == "CONNECT"


async def test_bad_proxy_authorization_is_400(serve, sink):
    host, port = await serve(http_proxy.HttpProxy(make_options()))
    status, _, _ = await asyncio.to_thread(
        _request, host, port, "GET", "http://example.org/", {"Proxy-Authorization": "Basic %%%"}
    )
    assert status == 400

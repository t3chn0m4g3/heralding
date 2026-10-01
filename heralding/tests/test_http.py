import asyncio
import base64
import http.client as httpclient

import pytest

from heralding.capabilities import http as http_capability
from heralding.tests.conftest import make_options


async def test_unauthenticated_request_gets_401(serve, sink):
    cap = http_capability.Http(make_options(banner=""))
    host, port = await serve(cap)

    def run():
        client = httpclient.HTTPConnection(host, port, timeout=5)
        client.request("GET", "/")
        response = client.getresponse()
        response.read()
        return response.status

    assert await asyncio.to_thread(run) == 401


async def test_basic_auth_is_logged(serve, sink):
    cap = http_capability.Http(make_options(banner=""))
    host, port = await serve(cap)

    def run():
        client = httpclient.HTTPConnection(host, port, timeout=5)
        token = base64.b64encode(b"james:bond").decode()
        client.request("GET", "/", headers={"Authorization": "Basic " + token})
        response = client.getresponse()
        response.read()
        return response.status

    assert await asyncio.to_thread(run) == 401
    attempts = await asyncio.to_thread(sink.wait_for_auth, 1)
    assert (attempts[0]["username"], attempts[0]["password"]) == ("james", "bond")


@pytest.mark.xfail(strict=True, reason="Server header fix lands in the HTTP hardening task")
async def test_server_header_does_not_reveal_python(serve, sink):
    cap = http_capability.Http(make_options(banner=""))
    host, port = await serve(cap)

    def run():
        client = httpclient.HTTPConnection(host, port, timeout=5)
        client.request("GET", "/")
        response = client.getresponse()
        response.read()
        return response.getheader("Server") or ""

    assert "Python" not in await asyncio.to_thread(run)

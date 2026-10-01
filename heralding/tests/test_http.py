import asyncio
import base64
import http.client as httpclient

from heralding.capabilities import http as http_capability
from heralding.tests.conftest import make_options


def _get(host, port, path="/", headers=None, method="GET", body=None):
    client = httpclient.HTTPConnection(host, port, timeout=5)
    client.request(method, path, body=body, headers=headers or {})
    response = client.getresponse()
    data = response.read()
    client.close()
    return response.status, dict(response.getheaders()), data


async def test_unauthenticated_request_gets_401(serve, sink):
    host, port = await serve(http_capability.Http(make_options(banner="")))
    status, headers, _ = await asyncio.to_thread(_get, host, port)
    assert status == 401
    assert headers["WWW-Authenticate"].startswith("Basic")


async def test_basic_auth_is_logged(serve, sink):
    host, port = await serve(http_capability.Http(make_options(banner="")))
    token = base64.b64encode(b"james:bond").decode()
    status, _, _ = await asyncio.to_thread(
        _get, host, port, "/", {"Authorization": "Basic " + token}
    )
    assert status == 401
    attempts = await asyncio.to_thread(sink.wait_for_auth, 1)
    assert (attempts[0]["username"], attempts[0]["password"]) == ("james", "bond")


async def test_server_header_from_banner_and_no_credential_echo(serve, sink):
    host, port = await serve(http_capability.Http(make_options(banner="Apache/2.4.58 (Ubuntu)")))
    token = base64.b64encode(b"u:p:q").decode()
    status, headers, body = await asyncio.to_thread(
        _get, host, port, "/", {"Authorization": "Basic " + token}
    )
    assert status == 401
    assert headers["Server"] == "Apache/2.4.58 (Ubuntu)"
    assert "Python" not in headers["Server"]
    assert b"Basic" not in body and token.encode() not in body
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("u", "p:q")


async def test_default_server_header_does_not_reveal_python(serve, sink):
    host, port = await serve(http_capability.Http(make_options(banner="")))
    _, headers, _ = await asyncio.to_thread(_get, host, port)
    assert "Python" not in headers["Server"]
    assert "BaseHTTP" not in headers["Server"]


async def test_bad_authorization_is_400(serve, sink):
    host, port = await serve(http_capability.Http(make_options(banner="")))
    status, _, _ = await asyncio.to_thread(_get, host, port, "/", {"Authorization": "Basic %%%"})
    assert status == 400


async def test_post_gets_401(serve, sink):
    host, port = await serve(http_capability.Http(make_options(banner="")))
    status, _, _ = await asyncio.to_thread(_get, host, port, "/login", None, "POST", b"x=1")
    assert status == 401


async def test_too_many_headers_is_431(serve, sink):
    host, port = await serve(http_capability.Http(make_options(banner="")))
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(b"GET / HTTP/1.1\r\n" + b"X-A: b\r\n" * 150 + b"\r\n")
    await writer.drain()
    status_line = await reader.readline()
    assert status_line.split()[1] == b"431"
    writer.close()


async def test_overlong_request_line_is_414(serve, sink):
    host, port = await serve(http_capability.Http(make_options(banner="")))
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(b"GET /" + b"a" * 9000 + b" HTTP/1.1\r\n\r\n")
    await writer.drain()
    status_line = await reader.readline()
    assert status_line.split()[1] == b"414"
    writer.close()

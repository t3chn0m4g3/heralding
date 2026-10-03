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
    status, _, _ = await asyncio.to_thread(
        _get, host, port, "/", {f"X-A-{i}": "b" for i in range(150)}
    )
    assert status == 431


async def test_overlong_request_line_is_414(serve, sink):
    host, port = await serve(http_capability.Http(make_options(banner="")))
    status, _, _ = await asyncio.to_thread(_get, host, port, "/" + "a" * 9000)
    assert status == 414


def _raw(host, port, method, path="/"):
    """http.client with an unusual method token; returns status line parts, headers, body."""
    client = httpclient.HTTPConnection(host, port, timeout=5)
    client.putrequest(method, path, skip_accept_encoding=True)
    client.endheaders()
    response = client.getresponse()
    data = response.read()
    client.close()
    return response.version, response.status, response.reason, data


async def test_responses_use_http_1_1_and_the_family_401_page(serve, sink):
    for banner, realm, marker in (
        ("Apache/2.4.62 (Debian)", "Restricted Content", b"<address>Apache/2.4.62 (Debian) Server"),
        ("nginx/1.24.0 (Ubuntu)", "Restricted", b"<title>401 Authorization Required</title>"),
        ("Microsoft-IIS/10.0", "127.0.0.1", b"401 - Unauthorized: Access is denied"),
    ):
        host, port = await serve(http_capability.Http(make_options(banner=banner)))
        version, status, reason, body = await asyncio.to_thread(_raw, host, port, "GET")
        assert (version, status, reason) == (11, 401, "Unauthorized")
        assert marker in body
        _, headers, _ = await asyncio.to_thread(_get, host, port)
        assert headers["WWW-Authenticate"] == f'Basic realm="{realm}"'
        assert headers["Connection"] == "close"


async def test_parser_errors_use_standard_reason_phrases(serve, sink):
    host, port = await serve(http_capability.Http(make_options(banner="nginx/1.24.0 (Ubuntu)")))
    for method, expected in (("GET X", (400, "Bad Request")), ("FOO", (501, "Not Implemented"))):
        _, status, reason, body = await asyncio.to_thread(_raw, host, port, method)
        assert (status, reason) == expected
        assert b"syntax" not in body and b"Unsupported" not in body
        assert b"<hr><center>nginx/1.24.0 (Ubuntu)</center>" in body

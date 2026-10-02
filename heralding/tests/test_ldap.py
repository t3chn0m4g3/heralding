import asyncio
import ssl

import ldap3
import pytest

from heralding.capabilities import ldap, ldaps
from heralding.capabilities.handlerbase import HandlerBase
from heralding.tests.conftest import make_options


def _server(host, port, use_ssl=False):
    tls = ldap3.Tls(validate=ssl.CERT_NONE) if use_ssl else None  # honeypot cert is self-signed
    return ldap3.Server(host, port=port, use_ssl=use_ssl, tls=tls, connect_timeout=5)


async def test_simple_bind_is_refused_and_logged(serve, sink):
    host, port = await serve(ldap.Ldap(make_options()))

    def run():
        conn = ldap3.Connection(
            _server(host, port),
            user="cn=admin,dc=corp,dc=local",
            password="Pa55w0rd",
            authentication=ldap3.SIMPLE,
            receive_timeout=5,
        )
        ok = conn.bind()
        return ok, conn.result["result"], conn.result["description"]

    ok, code, description = await asyncio.to_thread(run)
    assert ok is False
    assert (code, description) == (49, "invalidCredentials")
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("cn=admin,dc=corp,dc=local", "Pa55w0rd")
    assert attempt["protocol"] == "ldap"


async def test_anonymous_rootdse_search_shows_persona(serve, sink, windows_persona):
    host, port = await serve(ldap.Ldap(make_options()))

    def run():
        conn = ldap3.Connection(_server(host, port), receive_timeout=5)
        assert conn.bind()  # anonymous bind succeeds
        conn.search(
            "",
            "(objectClass=*)",
            search_scope=ldap3.BASE,
            attributes=["vendorName", "vendorVersion", "namingContexts", "supportedLDAPVersion"],
        )
        return conn.entries[0].entry_attributes_as_dict if conn.entries else {}

    attrs = await asyncio.to_thread(run)
    assert attrs["vendorName"] == [windows_persona.get("ldap", "vendor_name")]
    assert attrs["namingContexts"] == [windows_persona.get("ldap", "naming_context")]
    assert "3" in attrs["supportedLDAPVersion"]


async def test_ldaps_bind_over_tls(serve, sink, server_ssl_context):
    host, port = await serve(ldaps.Ldaps(make_options()), server_ssl_context)

    def run():
        conn = ldap3.Connection(
            _server(host, port, use_ssl=True),
            user="uid=bob,ou=people,dc=x",
            password="s",
            receive_timeout=5,
        )
        return conn.bind(), conn.result["result"]

    ok, code = await asyncio.to_thread(run)
    assert (ok, code) == (False, 49)
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["protocol"] == "ldaps"
    assert attempt["username"] == "uid=bob,ou=people,dc=x"


async def test_sasl_bind_mechanism_is_recorded(serve, sink):
    host, port = await serve(ldap.Ldap(make_options()))

    def run():
        conn = ldap3.Connection(
            _server(host, port),
            user="alice",
            password="pw",
            authentication=ldap3.SASL,
            sasl_mechanism=ldap3.PLAIN,
            sasl_credentials=(None, "alice", "pw"),
            receive_timeout=5,
        )
        ok, code = conn.bind(), conn.result["result"]
        conn.unbind()
        return ok, code

    ok, code = await asyncio.to_thread(run)
    assert ok is False and code in (7, 49)
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert ended[0]["auxiliary_data"]["sasl_mechanisms"] == ["PLAIN"]


async def test_non_utf8_password_in_simple_bind(serve, sink):
    host, port = await serve(ldap.Ldap(make_options()))
    reader, writer = await asyncio.open_connection(host, port)
    # BindRequest: messageID 1, version 3, name "u", simple password b"p\xe4"
    bind = b"\x60\x0a\x02\x01\x03\x04\x01u\x80\x02p\xe4"
    msg = b"\x30" + bytes([len(bind) + 3]) + b"\x02\x01\x01" + bind
    writer.write(msg)
    await writer.drain()
    resp = await asyncio.wait_for(reader.read(64), 5)
    assert resp[:1] == b"\x30"
    assert b"\x0a\x01\x31" in resp  # resultCode 49
    writer.close()
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("u", "p\\xe4")


async def test_oversized_or_garbage_message_is_a_client_error(serve, sink):
    host, port = await serve(ldap.Ldap(make_options(timeout=2)))
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(b"\x30\x84\x7f\xff\xff\xff")  # length 2 GB
    await writer.drain()
    assert await asyncio.wait_for(reader.read(), 5) == b""
    writer.close()
    for _ in range(40):
        if HandlerBase.global_sessions == 0:
            break
        await asyncio.sleep(0.05)
    assert HandlerBase.global_sessions == 0


@pytest.fixture
def windows_persona():
    import random

    from heralding.misc import persona

    p = persona.select_persona({"persona": "windows-server-2022"}, random.Random(3))
    HandlerBase.set_persona(p)
    yield p
    HandlerBase.set_persona(None)

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
            attributes=[
                "vendorName",
                "vendorVersion",
                "namingContexts",
                "supportedLDAPVersion",
                "objectClass",
                "supportedCapabilities",
                "dnsHostName",
                "configurationNamingContext",
            ],
        )
        return conn.entries[0].entry_attributes_as_dict if conn.entries else {}

    attrs = await asyncio.to_thread(run)
    assert not attrs.get("vendorName") and not attrs.get("vendorVersion")  # AD has neither
    assert attrs["namingContexts"] == [windows_persona.get("ldap", "naming_context")]
    assert "3" in attrs["supportedLDAPVersion"]
    assert attrs["objectClass"] == ["top"]
    assert "1.2.840.113556.1.4.800" in attrs["supportedCapabilities"]
    assert attrs["dnsHostName"] == [windows_persona.fqdn]
    assert attrs["configurationNamingContext"] == ["CN=Configuration," + attrs["namingContexts"][0]]


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


@pytest.fixture
def windows_persona():
    import random

    from heralding.misc import persona

    p = persona.select_persona({"persona": "windows-server-2022"}, random.Random(3))
    HandlerBase.set_persona(p)
    yield p
    HandlerBase.set_persona(None)


async def test_attempts_per_connection_are_capped(serve, sink):
    host, port = await serve(ldap.Ldap(make_options(max_attempts=3)))

    def run():
        conn = ldap3.Connection(_server(host, port), receive_timeout=5)
        conn.open()
        for i in range(10):
            try:
                conn.rebind(user=f"cn=u{i}", password="pw")
            except ldap3.core.exceptions.LDAPException:
                break
            if conn.closed:
                break

    await asyncio.to_thread(run)
    await asyncio.to_thread(sink.wait_for_auth, 3)
    await asyncio.sleep(0.2)
    first_session = sink.auth[0]["session_id"]
    assert sum(1 for a in sink.auth if a["session_id"] == first_session) == 3


async def test_advertised_sasl_mechanism_fails_as_invalid_credentials(serve, sink):
    host, port = await serve(ldap.Ldap(make_options()))

    def run():
        conn = ldap3.Connection(
            _server(host, port),
            authentication=ldap3.SASL,
            sasl_mechanism=ldap3.DIGEST_MD5,
            sasl_credentials=(None, "alice", "pw", None),
            receive_timeout=5,
        )
        conn.open()
        conn.bind()
        return conn.result["result"]

    assert await asyncio.to_thread(run) == 49  # invalidCredentials, not authMethodNotSupported


async def test_openldap_rootdse_has_no_vendor_attributes(serve, sink):
    host, port = await serve(ldap.Ldap(make_options(vendor_name="OpenLDAP")))

    def run():
        conn = ldap3.Connection(_server(host, port), receive_timeout=5)
        conn.bind()
        conn.search("", "(objectClass=*)", search_scope=ldap3.BASE, attributes=["*", "+"])
        return conn.entries[0].entry_attributes_as_dict

    attrs = await asyncio.to_thread(run)
    assert "OpenLDAProotDSE" in attrs["objectClass"]
    assert not attrs.get("vendorName") and not attrs.get("defaultNamingContext")


async def test_sicily_ntlm_bind_is_captured_on_active_directory(serve, sink, windows_persona):
    host, port = await serve(ldap.Ldap(make_options()))

    def run():
        conn = ldap3.Connection(
            _server(host, port),
            user="CORP\\alice",
            password="secret",
            authentication=ldap3.NTLM,  # ldap3 binds with Sicily NTLM, like impacket
            receive_timeout=5,
        )
        conn.open()
        assert not conn.bind()
        return conn.result

    result = await asyncio.to_thread(run)
    assert result["result"] == 49
    assert result["message"].startswith("80090308: LdapErr:")
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["username"] == "CORP\\alice"
    assert attempt["password"] is None
    assert attempt["password_hash"].startswith("alice::CORP:")


async def test_sicily_ntlm_is_unknown_to_openldap(serve, sink):
    host, port = await serve(ldap.Ldap(make_options()))

    def run():
        conn = ldap3.Connection(
            _server(host, port),
            user="CORP\\alice",
            password="secret",
            authentication=ldap3.NTLM,
            receive_timeout=5,
        )
        conn.open()
        conn.bind()
        return conn.result["result"]

    assert await asyncio.to_thread(run) == 7  # authMethodNotSupported
    assert sink.auth == []


async def test_gss_spnego_ntlm_bind_is_captured_on_active_directory(serve, sink, windows_persona):
    import spnego
    from ldap3.protocol.sasl.sasl import send_sasl_negotiation

    host, port = await serve(ldap.Ldap(make_options()))

    def run():
        # pyspnego produces the SPNEGO/NTLM tokens, ldap3 frames them as SASL binds
        client = spnego.client("CORP\\bob", "hunter2", protocol="negotiate",
                               options=spnego.NegotiateOptions.use_negotiate)  # fmt: skip
        conn = ldap3.Connection(_server(host, port), receive_timeout=5)
        conn.open()
        conn.sasl_mechanism = "GSS-SPNEGO"
        response = send_sasl_negotiation(conn, None, client.step())
        assert response["result"] == 14  # saslBindInProgress
        response = send_sasl_negotiation(conn, None, client.step(response["saslCreds"]))
        return response["result"]

    assert await asyncio.to_thread(run) == 49
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["username"] == "CORP\\bob"
    assert attempt["password_hash"].startswith("bob::CORP:")

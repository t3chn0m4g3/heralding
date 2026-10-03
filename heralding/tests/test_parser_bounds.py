import asyncio

import pytest
from ldap3.operation.search import compile_filter, parse_filter
from pyasn1.codec.ber.encoder import encode

from heralding.capabilities.mssql import Mssql
from heralding.libs import ber, tds
from heralding.misc.tls import minimum_version, upgrade_stream
from heralding.tests.conftest import make_options


def test_ldap_nested_filter_depth_is_carried_through_children():
    expression = "(objectClass=*)"
    for _ in range(ber.MAX_DEPTH + 2):
        expression = "(!" + expression + ")"
    parsed = parse_filter(expression, None, False, False, None, False)
    value = compile_filter(parsed.elements[0])
    with pytest.raises(ber.BerError, match="nesting too deep"):
        ber.decode_one(encode(value))


@pytest.mark.parametrize("version", ["garbage", "1.2.3.4.5", "256.0", "-1.2", "1.2.65536"])
def test_mssql_invalid_version_fails_at_initialization(version):
    with pytest.raises(ValueError):
        Mssql(make_options(version=version))


def test_unknown_tls_version_warns_and_falls_back(caplog):
    import ssl

    assert minimum_version("unknown") == ssl.TLSVersion.TLSv1_2
    assert "Unknown tls_min_version" in caplog.text


async def test_stream_upgrade_discards_buffered_plaintext(server_ssl_context):
    reader = asyncio.StreamReader()
    reader.feed_data(b"buffered untrusted plaintext")

    class Writer:
        async def start_tls(self, context, ssl_handshake_timeout):
            assert not reader._buffer
            assert context is server_ssl_context

    await upgrade_stream(reader, Writer(), server_ssl_context)


async def test_tds_eof_and_truncated_header_are_distinguished():
    reader = asyncio.StreamReader()
    reader.feed_eof()
    assert await tds.read_packet(reader) == (None, None)
    reader = asyncio.StreamReader()
    reader.feed_data(b"x")
    reader.feed_eof()
    with pytest.raises(tds.TdsError, match="short TDS header"):
        await tds.read_packet(reader)

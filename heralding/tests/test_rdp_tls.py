import asyncio
import ssl
import warnings

import pytest

from heralding.libs.msrdp.tls import TLS, TLSHandshakeError


@pytest.mark.parametrize(
    "version", [ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]
)
async def test_memorybio_tls_with_standard_ssl_client(server_ssl_context, version):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        server_ssl_context.minimum_version = ssl.TLSVersion.TLSv1
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.check_hostname = False
        client_context.verify_mode = ssl.CERT_NONE
        client_context.minimum_version = version
        client_context.maximum_version = version
    server_ssl_context.set_ciphers("DEFAULT:@SECLEVEL=0")
    client_context.set_ciphers("DEFAULT:@SECLEVEL=0")
    completed = asyncio.get_running_loop().create_future()

    async def handle(reader, writer):
        try:
            tls = TLS(writer, reader, context=server_ssl_context)
            await tls.do_tls_handshake()
            assert await tls.read_tls(5) == b"hello"
            await tls.write_tls(b"world")
            with pytest.raises(asyncio.IncompleteReadError):
                await tls.read_tls(1)
            completed.set_result(tls.version)
        except Exception as exc:
            completed.set_exception(exc)
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    try:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", server.sockets[0].getsockname()[1], ssl=client_context
        )
        writer.write(b"he")
        await writer.drain()
        await asyncio.sleep(0.01)
        writer.write(b"llo")
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(5), 5) == b"world"
        writer.close()
        await writer.wait_closed()
        assert await asyncio.wait_for(completed, 5) in ("TLSv1", "TLSv1.2", "TLSv1.3")
    finally:
        server.close()
        await server.wait_closed()


async def test_memorybio_handshake_eof_is_controlled(server_ssl_context):
    reader = asyncio.StreamReader()
    reader.feed_eof()

    class Writer:
        def write(self, _):
            pass

        async def drain(self):
            pass

    tls = TLS(Writer(), reader, context=server_ssl_context)
    with pytest.raises(TLSHandshakeError, match="connection closed"):
        await tls.do_tls_handshake()

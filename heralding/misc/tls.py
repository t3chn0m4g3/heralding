"""Shared TLS configuration and safe stream upgrades."""

import logging
import ssl

logger = logging.getLogger(__name__)


def minimum_version(value):
    version = getattr(ssl.TLSVersion, str(value), None)
    if version not in {
        ssl.TLSVersion.TLSv1,
        ssl.TLSVersion.TLSv1_1,
        ssl.TLSVersion.TLSv1_2,
        ssl.TLSVersion.TLSv1_3,
    }:
        logger.warning("Unknown tls_min_version %r; using TLSv1_2", value)
        return ssl.TLSVersion.TLSv1_2
    return version


async def upgrade_stream(reader, writer, context):
    # StreamReader has no public buffer-discard API. Bytes already delivered as plaintext
    # must not be interpreted as application commands after the TLS handshake.
    reader._buffer.clear()
    await writer.start_tls(context, ssl_handshake_timeout=10)

"""Shared TLS configuration and safe stream upgrades."""

import logging
import ssl

logger = logging.getLogger(__name__)


def minimum_version(value):
    return _version(value, "tls_min_version")


def maximum_version(value):
    return _version(value, "tls_max_version")


def _version(value, setting):
    version = getattr(ssl.TLSVersion, str(value), None)
    if version not in {
        ssl.TLSVersion.TLSv1,
        ssl.TLSVersion.TLSv1_1,
        ssl.TLSVersion.TLSv1_2,
        ssl.TLSVersion.TLSv1_3,
    }:
        logger.warning("Unknown %s %r; using TLSv1_2", setting, value)
        return ssl.TLSVersion.TLSv1_2
    return version


async def upgrade_stream(reader, writer, context):
    # StreamReader has no public buffer-discard API. Bytes already delivered as plaintext
    # must not be interpreted as application commands after the TLS handshake.
    reader._buffer.clear()
    await writer.start_tls(context, ssl_handshake_timeout=10)

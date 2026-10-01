import logging
import struct

from heralding.capabilities.handlerbase import HandlerBase
from heralding.misc.textutil import decode_lossless

logger = logging.getLogger(__name__)

SSL_REQUEST = 80877103
GSSENC_REQUEST = 80877104
CANCEL_REQUEST = 80877102
MAX_MESSAGE = 65536


class PostgreSQL(HandlerBase):
    NAME = "postgresql"

    async def execute_capability(self, reader, writer, session):
        await self._handle_session(session, reader, writer)

    async def _handle_session(self, session, reader, writer):
        # Encryption negotiation: clients may send GSSENCRequest and/or SSLRequest first,
        # or none at all. Decline each with 'N' and wait for the StartupMessage.
        data = await read_msg(reader)
        while len(data) == 4 and struct.unpack(">I", data)[0] in (SSL_REQUEST, GSSENC_REQUEST):
            writer.write(b"N")
            await writer.drain()
            data = await read_msg(reader)
        if len(data) < 4:
            raise ValueError("startup message too short")
        if struct.unpack(">I", data[:4])[0] == CANCEL_REQUEST:
            session.end_session()
            return

        session.activity()
        login_dict = parse_params(data[4:])  # skip the protocol version
        username = login_dict.get("user", "")

        # Request plain text password login (AuthenticationCleartextPassword)
        writer.write(struct.pack(">cII", b"R", 8, 3))
        await writer.drain()

        # PasswordMessage: 'p' + int32 length + cstring
        type_byte = await reader.readexactly(1)
        if type_byte != b"p":
            raise ValueError("expected PasswordMessage")
        password = decode_lossless((await read_msg(reader)).rstrip(b"\x00"))
        session.add_auth_attempt("plaintext", username=username, password=password)

        # Report login failure
        fail = [
            b"SFATAL\x00C28P01\x00",
            f'Mpassword authentication failed for user "{username}"'.encode(),
            b"\x00Fauth.c\x00L288\x00Rauth_failed\x00\x00",
        ]
        length = sum(len(f) for f in fail)
        writer.write(b"E" + struct.pack(">I", length + 4) + b"".join(fail))
        await writer.drain()

        session.end_session()


async def read_msg(reader):
    """Read one length-prefixed message body (length includes the 4 length bytes)."""
    header = await reader.readexactly(4)
    length = struct.unpack(">I", header)[0]
    if length < 4 or length > MAX_MESSAGE:
        raise ValueError("bad message length")
    return await reader.readexactly(length - 4)


def parse_params(data):
    """StartupMessage parameters: key\\0value\\0 ... \\0"""
    params = {}
    parts = data.split(b"\x00")
    for i in range(0, len(parts) - 1, 2):
        key = parts[i]
        if not key:
            break
        params[decode_lossless(key)] = decode_lossless(parts[i + 1])
    return params

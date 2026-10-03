"""Minimal TDS (MS-TDS) helpers for the MSSQL capability: packet framing, PRELOGIN and
LOGIN7 parsing, ERROR/DONE response building. Everything is length-bounded."""

import asyncio
import struct

MAX_PACKET = 32 * 1024

TYPE_SQL_BATCH = 0x01
TYPE_LOGIN7 = 0x10
TYPE_PRELOGIN = 0x12
TYPE_TABULAR = 0x04

PRELOGIN_VERSION = 0x00
PRELOGIN_ENCRYPTION = 0x01
PRELOGIN_INSTOPT = 0x02
PRELOGIN_THREADID = 0x03
PRELOGIN_MARS = 0x04
PRELOGIN_TERMINATOR = 0xFF

ENCRYPT_OFF = 0x00
ENCRYPT_ON = 0x01
ENCRYPT_NOT_SUP = 0x02
ENCRYPT_REQ = 0x03


class TdsError(ValueError):
    pass


async def read_packet(reader):
    """Return (type, payload) of one TDS packet, or (None, None) on EOF before a header."""
    try:
        header = await reader.readexactly(8)
    except asyncio.IncompleteReadError as exc:
        if not exc.partial:
            return None, None
        raise TdsError("short TDS header") from None
    packet_type, _status, length = header[0], header[1], struct.unpack(">H", header[2:4])[0]
    if length < 8 or length > MAX_PACKET:
        raise TdsError("bad TDS packet length")
    payload = await reader.readexactly(length - 8)
    return packet_type, payload


def packet(packet_type: int, payload: bytes, status: int = 0x01) -> bytes:
    return struct.pack(">BBHHBB", packet_type, status, 8 + len(payload), 0, 1, 0) + payload


def parse_prelogin(payload: bytes) -> dict[int, bytes]:
    options = {}
    pos = 0
    while pos < len(payload) and payload[pos] != PRELOGIN_TERMINATOR:
        if pos + 5 > len(payload):
            raise TdsError("truncated PRELOGIN option")
        token = payload[pos]
        offset, size = struct.unpack(">HH", payload[pos + 1 : pos + 5])
        if offset + size > len(payload):
            raise TdsError("PRELOGIN option out of range")
        options[token] = payload[offset : offset + size]
        pos += 5
        if len(options) > 16:
            raise TdsError("too many PRELOGIN options")
    return options


def build_prelogin(version: tuple[int, int, int, int], encryption: int = ENCRYPT_NOT_SUP) -> bytes:
    """PRELOGIN response with VERSION, ENCRYPTION, INSTOPT, THREADID and MARS options."""
    values = [
        (PRELOGIN_VERSION, struct.pack(">BBHH", version[0], version[1], version[2], version[3])),
        (PRELOGIN_ENCRYPTION, bytes([encryption])),
        (PRELOGIN_INSTOPT, b"\x00"),
        (PRELOGIN_THREADID, b"\x00\x00\x00\x00"),
        (PRELOGIN_MARS, b"\x00"),
    ]
    header_len = len(values) * 5 + 1
    offsets = b""
    data = b""
    for token, value in values:
        offsets += struct.pack(">BHH", token, header_len + len(data), len(value))
        data += value
    return offsets + bytes([PRELOGIN_TERMINATOR]) + data


def _ucs2(data: bytes, offset: int, chars: int) -> str:
    end = offset + chars * 2
    if end > len(data):
        raise TdsError("LOGIN7 string out of range")
    return data[offset:end].decode("utf-16-le", "replace")


def decode_password(data: bytes) -> bytes:
    """LOGIN7 passwords are obfuscated byte-wise (nibble swap, then XOR 0xA5); undo it."""
    out = bytearray()
    for byte in data:
        byte ^= 0xA5
        out.append(((byte & 0x0F) << 4) | (byte >> 4))
    return bytes(out)


def parse_login7(payload: bytes) -> dict:
    """Return the client-supplied strings of a LOGIN7 packet (host, user, password, app, ...)."""
    if len(payload) < 94:
        raise TdsError("short LOGIN7")
    total = struct.unpack("<I", payload[0:4])[0]
    if total > len(payload):
        raise TdsError("LOGIN7 length exceeds packet")
    tds_version = struct.unpack("<I", payload[4:8])[0]
    # OffsetLength block starts at byte 36: (offset, length) pairs of UCS-2 char counts
    fields = {}
    names = [
        "hostname",
        "username",
        "password",
        "app_name",
        "server_name",
        "unused",
        "library",
        "language",
        "database",
    ]
    pos = 36
    for name in names:
        offset, length = struct.unpack("<HH", payload[pos : pos + 4])
        pos += 4
        if length > 1024:
            raise TdsError("LOGIN7 field too long")
        fields[name] = (offset, length)
    result = {"tds_version": f"{tds_version:#010x}"}
    for name in (
        "hostname",
        "username",
        "app_name",
        "server_name",
        "library",
        "language",
        "database",
    ):
        offset, length = fields[name]
        result[name] = _ucs2(payload, offset, length) if length else ""
    offset, length = fields["password"]
    if length:
        end = offset + length * 2
        if end > len(payload):
            raise TdsError("password out of range")
        result["password"] = decode_password(payload[offset:end]).decode("utf-16-le", "replace")
    else:
        result["password"] = ""
    return result


def build_login_failed(username: str, server_name: str) -> bytes:
    """ERROR token 18456 (login failed) followed by a DONE token."""
    message = f"Login failed for user '{username}'."
    msg = message.encode("utf-16-le")
    srv = server_name.encode("utf-16-le")
    error = (
        struct.pack("<IBB", 18456, 1, 14)
        + struct.pack("<H", len(message))
        + msg
        + bytes([len(server_name)])
        + srv
        + b"\x00"  # proc name length
        + struct.pack("<I", 1)  # line number
    )
    error_token = b"\xaa" + struct.pack("<H", len(error)) + error
    done_token = b"\xfd" + struct.pack("<HHQ", 0x0002, 0, 0)  # DONE_ERROR
    return error_token + done_token

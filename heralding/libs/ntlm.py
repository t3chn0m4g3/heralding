"""Bounded NTLM challenge and credential-material helpers for honeypot protocols.

Wire definitions: Microsoft MS-NLMP sections 2.2.1.2 and 2.2.1.3.
No credentials are authenticated or forwarded.
"""

import struct

from heralding.libs import ber

SIGNATURE = b"NTLMSSP\0"
NTLM_OID = ber.encode(0x06, bytes.fromhex("2b06010401823702020a"))
SPNEGO_OID = ber.encode(0x06, bytes.fromhex("2b0601050502"))


def initial_token():
    mechanisms = ber.encode(0xA0, ber.sequence(NTLM_OID))
    return ber.encode(0x60, SPNEGO_OID + ber.encode(0xA0, ber.sequence(mechanisms)))


def response_token(token):
    return ber.encode(
        0xA1,
        ber.sequence(
            ber.encode(0xA0, ber.enumerated(1)),
            ber.encode(0xA1, NTLM_OID),
            ber.encode(0xA2, ber.octet_string(token)),
        ),
    )


def extract_message(token):
    offset = token.find(SIGNATURE)
    if offset < 0 or len(token) - offset < 12:
        raise ValueError("missing NTLM message")
    return token[offset:]


def challenge_message(challenge, hostname, domain, fqdn, *, signing=False):
    target = domain.encode("utf-16-le")
    av = b""
    for kind, value in ((1, hostname.upper()), (2, domain.upper()), (3, fqdn), (4, domain)):
        encoded = value.encode("utf-16-le")
        av += struct.pack("<HH", kind, len(encoded)) + encoded
    av += struct.pack("<HH", 0, 0)
    flags = 0xA0888205  # Unicode, NTLM, extended security, target info, 128/56-bit support
    if signing:
        flags |= 0x40000030  # key exchange, signing and sealing for CredSSP
    return (
        SIGNATURE
        + struct.pack("<IHHII", 2, len(target), len(target), 48, flags)
        + challenge
        + b"\0" * 8
        + struct.pack("<HHI", len(av), len(av), 48 + len(target))
        + target
        + av
    )


def _field(message, position):
    if position + 8 > len(message):
        raise ValueError("short NTLM field")
    length, maximum, offset = struct.unpack_from("<HHI", message, position)
    if length > 8192 or maximum < length or offset + length > len(message):
        raise ValueError("NTLM field out of range")
    if length and offset < 64:
        raise ValueError("NTLM field overlaps header")
    return message[offset : offset + length]


def authenticate(message, challenge):
    if (
        len(message) < 64
        or message[:8] != SIGNATURE
        or struct.unpack_from("<I", message, 8)[0] != 3
    ):
        raise ValueError("expected NTLM authenticate")
    flags = struct.unpack_from("<I", message, 60)[0]
    encoding = "utf-16-le" if flags & 1 else "cp437"
    domain = _field(message, 28).decode(encoding, "replace")
    username = _field(message, 36).decode(encoding, "replace")
    workstation = _field(message, 44).decode(encoding, "replace")
    lm = _field(message, 12)
    nt = _field(message, 20)
    if len(nt) > 24:
        method = "ntlmv2"
        password_hash = f"{username}::{domain}:{challenge.hex()}:{nt[:16].hex()}:{nt[16:].hex()}"
    elif len(nt) == 24:
        method = "ntlmv1"
        password_hash = f"{username}::{domain}:{lm.hex()}:{nt.hex()}:{challenge.hex()}"
    else:
        raise ValueError("missing NTLM challenge response")
    return username, domain, workstation, method, password_hash

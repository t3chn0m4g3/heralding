"""Bounded NTLM challenge and credential-material helpers for honeypot protocols.

Wire definitions: Microsoft MS-NLMP sections 2.2.1.2 and 2.2.1.3.
No credentials are authenticated or forwarded.
"""

import struct
import time

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


def netbios_domain(domain):
    """NetBIOS form of a DNS domain: first label, upper case, at most 15 characters."""
    return (domain.split(".")[0] or "WORKGROUP").upper()[:15]


def parse_version(text):
    """'10.0.20348' -> (10, 0, 20348); Samba-style 6.1.0 for anything unparsable."""
    try:
        major, minor, build = (int(part) for part in str(text).split("."))
        return major, minor, build
    except ValueError:
        return 6, 1, 0


# signing, sealing and key exchange are granted when the client asks for them, as Windows does
ECHOED_FLAGS = 0x40000030


def challenge_message(
    challenge, hostname, domain, fqdn, *, signing=False, version=(6, 1, 0), client_flags=0
):
    nb_domain = netbios_domain(domain)
    target = nb_domain.encode("utf-16-le")
    av = b""
    pairs = ((1, hostname.upper()), (2, nb_domain), (3, fqdn), (4, domain), (5, domain))
    for kind, value in pairs:
        encoded = value.encode("utf-16-le")
        av += struct.pack("<HH", kind, len(encoded)) + encoded
    filetime = int((time.time() + 11644473600) * 10_000_000)
    av += struct.pack("<HHQ", 7, 8, filetime)
    av += struct.pack("<HH", 0, 0)
    # Unicode, NTLM, extended security, domain target, target info, version, 128/56-bit
    flags = 0xA2898205
    flags |= client_flags & ECHOED_FLAGS
    if signing:
        flags |= ECHOED_FLAGS  # CredSSP always needs them
    major, minor, build = version
    return (
        SIGNATURE
        + struct.pack("<IHHII", 2, len(target), len(target), 56, flags)
        + challenge
        + b"\0" * 8
        + struct.pack("<HHI", len(av), len(av), 56 + len(target))
        + struct.pack("<BBH3xB", major, minor, build, 15)
        + target
        + av
    )


def challenge_token(client_token, challenge, persona, *, signing=False):
    """The server's answer to a client NEGOTIATE for the persona's host, wrapped in SPNEGO
    when the client wrapped its own token, raw NTLM otherwise."""
    host = (persona.netbios or persona.hostname) if persona else "SERVER"
    domain = persona.domain if persona else "WORKGROUP"
    fqdn = persona.fqdn if persona else "server.local"
    version = parse_version(persona.os_version if persona else "")
    negotiate = extract_message(client_token)
    client_flags = struct.unpack_from("<I", negotiate, 12)[0] if len(negotiate) >= 16 else 0
    reply = challenge_message(
        challenge, host, domain, fqdn, signing=signing, version=version, client_flags=client_flags
    )
    return reply if client_token.startswith(SIGNATURE) else response_token(reply)


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

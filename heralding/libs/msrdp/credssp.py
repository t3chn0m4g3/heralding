"""Bounded CredSSP NTLM capture (MS-CSSP 2.2.1 and 3.1.5).

Stop after NTLM authentication with STATUS_LOGON_FAILURE. No credential
delegation, authentication, public-key-binding bypass or forwarding takes place.
"""

import secrets
import struct

from heralding.libs import ber, ntlm

LOGON_FAILURE = 0xC000006D


async def read_request(tls):
    header = await tls.read_tls(2)
    if header[0] != 0x30:
        raise ValueError("expected CredSSP sequence")
    length = header[1]
    if length & 0x80:
        count = length & 0x7F
        if not 1 <= count <= 4:
            raise ValueError("invalid CredSSP length")
        extra = await tls.read_tls(count)
        header += extra
        length = int.from_bytes(extra, "big")
    if length > ber.MAX_MESSAGE:
        raise ValueError("CredSSP message too large")
    message, end = ber.decode_one(header + await tls.read_tls(length))
    if end != len(header) + length:
        raise ValueError("invalid CredSSP message")
    fields = {}
    for field in message.children():
        if field.tag not in range(0xA0, 0xA6) or field.tag in fields:
            raise ValueError("invalid CredSSP field")
        fields[field.tag] = field.children()
    version = fields.get(0xA0, [])
    if len(version) != 1 or version[0].tag != 2 or not 2 <= version[0].as_int() <= 255:
        raise ValueError("invalid CredSSP version")
    tokens = fields.get(0xA1, [])
    if len(tokens) != 1 or tokens[0].tag != 0x30:
        raise ValueError("missing CredSSP negotiation token")
    items = tokens[0].children()
    if len(items) != 1 or items[0].tag != 0x30:
        raise ValueError("invalid CredSSP negotiation data")
    token_fields = items[0].children()
    if len(token_fields) != 1 or token_fields[0].tag != 0xA0:
        raise ValueError("invalid CredSSP negotiation token")
    token = token_fields[0].children()
    if len(token) != 1 or token[0].tag != 4:
        raise ValueError("invalid CredSSP token type")
    return min(version[0].as_int(), 6), token[0].value


def response(version, token=None, error=None):
    parts = [ber.encode(0xA0, ber.integer(version))]
    if token is not None:
        parts.append(
            ber.encode(0xA1, ber.sequence(ber.sequence(ber.encode(0xA0, ber.octet_string(token)))))
        )
    if error is not None and version >= 3:
        parts.append(ber.encode(0xA4, ber.integer(error)))
    return ber.sequence(*parts)


async def capture(tls, session, persona=None):
    version, token = await read_request(tls)
    message = ntlm.extract_message(token)
    if struct.unpack_from("<I", message, 8)[0] != 1:
        raise ValueError("expected CredSSP NTLM negotiate")
    challenge = secrets.token_bytes(8)
    host = persona.netbios or persona.hostname if persona else "SERVER"
    domain = persona.domain if persona else "WORKGROUP"
    fqdn = persona.fqdn if persona else "server.local"
    os_version = ntlm.parse_version(persona.os_version if persona else "")
    reply = ntlm.challenge_message(challenge, host, domain, fqdn, signing=True, version=os_version)
    if not token.startswith(ntlm.SIGNATURE):
        reply = ntlm.response_token(reply)
    await tls.write_tls(response(version, reply))
    _, token = await read_request(tls)
    username, domain, workstation, method, password_hash = ntlm.authenticate(
        ntlm.extract_message(token), challenge
    )
    session.set_auxiliary_data(
        {
            "domain": domain,
            "workstation": workstation,
            "tls_version": tls.version,
            "rdp_security": "nla",
            "credssp_version": version,
        }
    )
    session.add_auth_attempt(
        method,
        username=f"{domain}\\{username}" if domain else username,
        password_hash=password_hash,
    )
    await tls.write_tls(response(version, error=LOGON_FAILURE))
    session.end_session()

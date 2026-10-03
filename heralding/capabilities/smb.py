"""SMB2 negotiation and NTLM credential capture; every login is refused.

SMB1 multi-protocol negotiation upgrades to SMB2. SMB 2.0.2 / 2.1 are offered;
file operations, Kerberos authentication and SMB3 encryption are not supported.
"""

import asyncio
import secrets
import struct
import time
import uuid

from heralding.capabilities.handlerbase import HandlerBase
from heralding.libs import ntlm

MAX_MESSAGE = 65536
MORE_PROCESSING = 0xC0000016
LOGIN_FAILURE = 0xC000006D
NOT_SUPPORTED = 0xC00000BB
SMB2 = b"\xfeSMB"


def _response(request, command, body, status=0, session_id=0):
    message_id = struct.unpack_from("<Q", request, 24)[0] if request[:4] == SMB2 else 0
    header = struct.pack(
        "<4sHHIHHIIQIIQ16s",
        SMB2,
        64,
        1,
        status,
        command,
        64,
        1,
        0,
        message_id,
        0,
        0,
        session_id,
        b"\0" * 16,
    )
    message = header + body
    return len(message).to_bytes(4, "big") + message


async def _read_message(reader):
    try:
        head = await reader.readexactly(4)
    except asyncio.IncompleteReadError as exc:
        if not exc.partial:
            return None
        raise
    if head[0] != 0:
        raise ValueError("unsupported NetBIOS message type")
    size = int.from_bytes(head[1:], "big")
    if not 32 <= size <= MAX_MESSAGE:
        raise ValueError("SMB message length out of range")
    return await reader.readexactly(size)


class Smb(HandlerBase):
    NAME = "smb"

    def __init__(self, options):
        super().__init__(options)
        persona = HandlerBase.persona
        self.guid = (
            uuid.uuid5(uuid.NAMESPACE_DNS, persona.fqdn).bytes_le
            if persona
            else uuid.uuid4().bytes_le
        )

    def _negotiate(self, request):
        if request[:4] == b"\xffSMB":
            if request[4] != 0x72 or b"SMB 2." not in request:
                raise ValueError("only SMB2 multi-protocol negotiation is supported")
            dialect = 0x0202
        else:
            if len(request) < 100 or struct.unpack_from("<H", request, 64)[0] != 36:
                raise ValueError("short SMB2 negotiate")
            count = struct.unpack_from("<H", request, 66)[0]
            if not 1 <= count <= 32 or 100 + count * 2 > len(request):
                raise ValueError("invalid dialect list")
            offered = struct.unpack_from(f"<{count}H", request, 100)
            supported = [d for d in offered if d in (0x0202, 0x0210)]
            if not supported:
                return _response(request, 0, struct.pack("<HBBI", 9, 0, 0, 0), NOT_SUPPORTED)
            dialect = max(supported)
        token = ntlm.initial_token()
        filetime = int((time.time() + 11644473600) * 10000000)
        body = struct.pack(
            "<HHHH16sIIIIQQHHI",
            65,
            1,
            dialect,
            0,
            self.guid,
            0,
            MAX_MESSAGE,
            MAX_MESSAGE,
            MAX_MESSAGE,
            filetime,
            0,
            128,
            len(token),
            0,
        )
        return _response(request, 0, body + token)

    async def execute_capability(self, reader, writer, session):
        challenge = secrets.token_bytes(8)
        session_id = secrets.randbits(63) or 1
        challenged = False
        negotiated = False
        for _ in range(8):
            request = await _read_message(reader)
            if request is None:
                break
            if request[:4] == b"\xffSMB":
                command = 0
            elif request[:4] == SMB2 and len(request) >= 64:
                if (
                    struct.unpack_from("<H", request, 4)[0] != 64
                    or struct.unpack_from("<I", request, 20)[0]
                ):
                    raise ValueError("invalid or compound SMB2 header")
                command = struct.unpack_from("<H", request, 12)[0]
            else:
                raise ValueError("invalid SMB header")
            session.record_command({0: "NEGOTIATE", 1: "SESSION_SETUP"}.get(command, "UNSUPPORTED"))
            if command == 0:
                response = self._negotiate(request)
                negotiated = True
            elif command == 1 and negotiated:
                if len(request) < 88:
                    raise ValueError("short session setup")
                offset, length = struct.unpack_from("<HH", request, 76)
                if offset < 88 or length > MAX_MESSAGE or offset + length > len(request):
                    raise ValueError("invalid security buffer")
                token = request[offset : offset + length]
                message = ntlm.extract_message(token)
                kind = struct.unpack_from("<I", message, 8)[0]
                if kind == 1:
                    persona = HandlerBase.persona
                    host = persona.netbios or persona.hostname if persona else "FILESERVER"
                    domain = persona.domain if persona else "WORKGROUP"
                    fqdn = persona.fqdn if persona else "fileserver.local"
                    challenge_token = ntlm.challenge_message(challenge, host, domain, fqdn)
                    # NTLM may be used directly or wrapped in SPNEGO.
                    if not token.startswith(ntlm.SIGNATURE):
                        challenge_token = ntlm.response_token(challenge_token)
                    body = struct.pack("<HHHH", 9, 0, 72, len(challenge_token)) + challenge_token
                    response = _response(request, 1, body, MORE_PROCESSING, session_id)
                    challenged = True
                elif kind == 3 and challenged:
                    username, domain, workstation, method, password_hash = ntlm.authenticate(
                        message, challenge
                    )
                    session.set_auxiliary_data({"domain": domain, "workstation": workstation})
                    session.add_auth_attempt(
                        method,
                        username=f"{domain}\\{username}" if domain else username,
                        password_hash=password_hash,
                    )
                    response = _response(
                        request, 1, struct.pack("<HBBI", 9, 0, 0, 0), LOGIN_FAILURE, session_id
                    )
                    writer.write(response)
                    await writer.drain()
                    # Let the client consume STATUS_LOGON_FAILURE and close its
                    # stream; an immediate EOF races smbprotocol's receiver thread.
                    await reader.read(1)
                    break
                else:
                    raise ValueError("unexpected NTLM message")
            else:
                response = _response(
                    request, command, struct.pack("<HBBI", 9, 0, 0, 0), NOT_SUPPORTED, session_id
                )
            writer.write(response)
            await writer.drain()
        session.end_session()

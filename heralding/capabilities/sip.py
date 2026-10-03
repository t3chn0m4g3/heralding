# Copyright (C) 2026 Heralding contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""SIP capability (UDP and TCP): REGISTER/INVITE are challenged, offered credentials are
logged (hashcat 11400 layout), OPTIONS gets a persona User-Agent."""

import hashlib
import hmac
import logging
import re
import secrets
import time

from heralding.capabilities.handlerbase import DatagramHandlerBase
from heralding.misc.textutil import decode_lossless

logger = logging.getLogger(__name__)

MAX_MESSAGE = 8192
NONCE_LIFETIME = 3600  # seconds a challenge nonce is accepted for
_HEX = set("0123456789abcdef")
_REQUEST_LINE = re.compile(r"^([A-Z]+) (\S+) SIP/2\.0$")
_PARAM = re.compile(r'(\w+)=("([^"]*)"|([^,\s]*))')
COPIED_HEADERS = ("via", "from", "to", "call-id", "cseq")
HEADER_LABELS = {"via": "Via", "from": "From", "to": "To", "call-id": "Call-ID", "cseq": "CSeq"}


def parse_message(data: bytes):
    """Return (method, request_uri, headers) or None when this is not a SIP request."""
    text = decode_lossless(data)
    head = text.partition("\r\n\r\n")[0]
    lines = head.split("\r\n")
    match = _REQUEST_LINE.match(lines[0].strip())
    if not match:
        return None
    headers = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep and len(headers) < 64:
            headers.setdefault(name.strip().lower(), value.strip())
    return match.group(1), match.group(2), headers


def parse_digest(value: str) -> dict:
    if not value.lower().startswith("digest "):
        return {}
    params = {}
    for m in _PARAM.finditer(value[7:]):
        params[m.group(1).lower()] = m.group(3) if m.group(3) is not None else m.group(4)
    return params


class Sip(DatagramHandlerBase):
    NAME = "sip"
    TRANSPORT = "tcp+udp"

    def __init__(self, options):
        super().__init__(options)
        self._nonce_key = secrets.token_bytes(32)

    def _nonce(self, source_ip, issued=None):
        """Nonce bound to the source address: hex timestamp + HMAC. Over UDP only a source that
        received our challenge can answer it, so spoofed senders never reach the auth log."""
        stamp = f"{int(time.time() if issued is None else issued) & 0xFFFFFFFF:08x}"
        mac = hmac.new(self._nonce_key, f"{stamp}|{source_ip}".encode(), hashlib.sha256)
        return stamp + mac.hexdigest()[:24]

    def _nonce_valid(self, nonce, source_ip):
        # exactly our format: 32 lower-case hex digits (compare_digest needs ASCII)
        if len(nonce) != 32 or not set(nonce) <= _HEX:
            return False
        issued = int(nonce[:8], 16)
        if not 0 <= time.time() - issued <= NONCE_LIFETIME:
            return False
        return hmac.compare_digest(nonce, self._nonce(source_ip, issued))

    def _challenge(self, session, headers):
        challenge = (
            f'Digest realm="{self._realm()}", nonce="{self._nonce(session.source_ip)}", '
            "algorithm=MD5"
        )
        return self._build(401, "Unauthorized", headers, ["WWW-Authenticate: " + challenge])

    def valid_datagram(self, data):
        return len(data) <= MAX_MESSAGE and parse_message(data) is not None

    def _realm(self):
        persona = type(self).persona
        return persona.domain if persona is not None and persona.domain else "sip.local"

    def _build(self, code, reason, headers, extra=()):
        lines = [f"SIP/2.0 {code} {reason}"]
        for name in COPIED_HEADERS:
            if name in headers:
                label = HEADER_LABELS[name]
                lines.append(f"{label}: {headers[name]}")
        lines.extend(extra)
        lines.append("User-Agent: " + self.persona_value("user_agent", "Asterisk PBX"))
        lines.append("Content-Length: 0")
        return ("\r\n".join(lines) + "\r\n\r\n").encode()

    def handle_datagram(self, data, session, transport="UDP"):
        parsed = parse_message(data[:MAX_MESSAGE])
        if parsed is None:
            return None  # responses, keep-alives and garbage are ignored
        method, uri, headers = parsed
        session.record_command(f"{method} {uri}"[:256])
        if method == "OPTIONS":
            allow = "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER"
            return self._build(200, "OK", headers, [allow])
        if method not in ("REGISTER", "INVITE"):
            return self._build(405, "Method Not Allowed", headers)
        creds = parse_digest(headers.get("authorization") or headers.get("proxy-authorization", ""))
        if creds.get("username"):
            if transport == "TCP" or self._nonce_valid(creds.get("nonce", ""), session.source_ip):
                self._log_attempt(session, method, uri, creds)
            else:
                logger.debug("%s credentials with a foreign nonce ignored", self.NAME)
        # like Asterisk: wrong credentials get a fresh challenge, not a 403
        return self._challenge(session, headers)

    @staticmethod
    def _log_attempt(session, method, uri, creds):
        # hashcat 11400: tag, server, client, user, realm, method,
        # URI prefix/resource/suffix, nonce, cnonce, nc, qop, directive, response.
        # the digest is computed over the uri directive of the credentials, not the Request-URI
        scheme, _, rest = (creds.get("uri") or uri).partition(":")
        fields = [
            "$sip$", "", "", creds.get("username", ""), creds.get("realm", ""), method,
            scheme or "sip", rest, "", creds.get("nonce", ""), creds.get("cnonce", ""),
            creds.get("nc", ""), creds.get("qop", ""), "MD5", creds.get("response", ""),
        ]  # fmt: skip
        session.set_auxiliary_data(
            {"realm": creds.get("realm", ""), "request_uri": uri, "uri": creds.get("uri", "")}
        )
        session.add_auth_attempt(
            "digest", username=creds.get("username", ""), password_hash="*".join(fields)
        )

    async def execute_capability(self, reader, writer, session):
        """Keep the TCP stream open for the client's challenge response."""
        for _ in range(
            int((self.options.get("protocol_specific_data") or {}).get("max_attempts", 10))
        ):
            data = await reader.readuntil(b"\r\n\r\n")
            if len(data) > MAX_MESSAGE:
                raise ValueError("SIP message too large")
            parsed = parse_message(data)
            if parsed is None:
                break
            body_length = int(parsed[2].get("content-length", "0"))
            if not 0 <= body_length <= MAX_MESSAGE - len(data):
                raise ValueError("SIP body too large")
            await reader.readexactly(body_length)
            reply = self.handle_datagram(data, session, transport="TCP")
            if reply:
                writer.write(reply)
                await writer.drain()
        session.end_session()

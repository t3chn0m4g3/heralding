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

import logging
import re
import secrets

from heralding.capabilities.handlerbase import DatagramHandlerBase
from heralding.misc.textutil import decode_lossless

logger = logging.getLogger(__name__)

MAX_MESSAGE = 8192
_REQUEST_LINE = re.compile(r"^([A-Z]+) (\S+) SIP/2\.0$")
_PARAM = re.compile(r'(\w+)=("([^"]*)"|([^,\s]*))')
COPIED_HEADERS = ("via", "from", "to", "call-id", "cseq")


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

    def _realm(self):
        persona = type(self).persona
        return persona.domain if persona is not None and persona.domain else "sip.local"

    def _build(self, code, reason, headers, extra=()):
        lines = [f"SIP/2.0 {code} {reason}"]
        for name in COPIED_HEADERS:
            if name in headers:
                label = "CSeq" if name == "cseq" else name.title()
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
        if not creds.get("username"):
            challenge = (
                f'Digest realm="{self._realm()}", nonce="{secrets.token_hex(16)}", algorithm=MD5'
            )
            return self._build(401, "Unauthorized", headers, ["WWW-Authenticate: " + challenge])
        self._log_attempt(session, method, uri, creds)
        # like Asterisk: wrong credentials get a fresh challenge, not a 403
        challenge = (
            f'Digest realm="{self._realm()}", nonce="{secrets.token_hex(16)}", algorithm=MD5'
        )
        return self._build(401, "Unauthorized", headers, ["WWW-Authenticate: " + challenge])

    @staticmethod
    def _log_attempt(session, method, uri, creds):
        # hashcat 11400 layout: $sip$*server*client*user*realm*method*proto*prefix*resource*suffix*nonce*cnonce*nc*qop*directive*response
        # the digest is computed over the uri directive of the credentials, not the Request-URI
        scheme, _, rest = (creds.get("uri") or uri).partition(":")
        fields = [
            "$sip$", "", "", creds.get("username", ""), creds.get("realm", ""), method,
            scheme or "sip", "", rest, "", creds.get("nonce", ""), creds.get("cnonce", ""),
            creds.get("nc", ""), creds.get("qop", ""), "MD5", creds.get("response", ""),
        ]  # fmt: skip
        session.set_auxiliary_data(
            {"realm": creds.get("realm", ""), "request_uri": uri, "uri": creds.get("uri", "")}
        )
        session.add_auth_attempt(
            "digest", username=creds.get("username", ""), password_hash="*".join(fields)
        )

    async def execute_capability(self, reader, writer, session):
        """TCP transport: one request per connection, same reply logic."""
        data = await reader.read(MAX_MESSAGE)
        reply = self.handle_datagram(data, session, transport="TCP")
        if reply:
            writer.write(reply)
            await writer.drain()
        session.end_session()

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

"""LDAP capability: binds fail with invalidCredentials, the RootDSE shows persona values."""

import logging
import secrets
import struct

from heralding.capabilities.handlerbase import HandlerBase
from heralding.libs import ber, ntlm
from heralding.misc.textutil import decode_lossless

logger = logging.getLogger(__name__)

BIND_REQUEST, BIND_RESPONSE = 0x60, 0x61
UNBIND_REQUEST = 0x42
SEARCH_REQUEST, SEARCH_RESULT_ENTRY, SEARCH_RESULT_DONE = 0x63, 0x64, 0x65
ABANDON_REQUEST = 0x50
EXTENDED_REQUEST, EXTENDED_RESPONSE = 0x77, 0x78
RESULT_RESPONSES = {0x66: 0x67, 0x68: 0x69, 0x4A: 0x6B, 0x6C: 0x6D, 0x6E: 0x6F}
OP_NAMES = {
    0x60: "BIND", 0x42: "UNBIND", 0x63: "SEARCH", 0x50: "ABANDON", 0x77: "EXTENDED",
    0x66: "MODIFY", 0x68: "ADD", 0x4A: "DELETE", 0x6C: "MODDN", 0x6E: "COMPARE",
}  # fmt: skip

SUCCESS, AUTH_METHOD_NOT_SUPPORTED, SASL_BIND_IN_PROGRESS, INVALID_CREDENTIALS = 0, 7, 14, 49
# Active Directory's Sicily NTLM bind: package discovery, negotiate, response
SICILY_DISCOVERY, SICILY_NEGOTIATE, SICILY_RESPONSE = 0x89, 0x8A, 0x8B
SERVER_SASL_CREDS = 0x87
AD_INVALID_CREDENTIALS = (
    "80090308: LdapErr: DSID-0C090569, comment: AcceptSecurityContext error, data 52e, v4563\x00"
)
INSUFFICIENT_ACCESS, UNWILLING_TO_PERFORM = 50, 53
MAX_SASL_RECORDS = 20


def ldap_result(code, diagnostic="", matched_dn=""):
    return ber.enumerated(code) + ber.octet_string(matched_dn) + ber.octet_string(diagnostic)


class Ldap(HandlerBase):
    NAME = "ldap"

    def __init__(self, options):
        super().__init__(options)
        psd = options.get("protocol_specific_data") or {}
        self.max_attempts = int(psd.get("max_attempts", 10))

    async def execute_capability(self, reader, writer, session):
        state = {"sasl": [], "challenge": None}
        while session.connected:
            raw = await self._read_message(reader)
            if raw is None:
                break
            parts = ber.decode_one(raw)[0].children()
            if len(parts) < 2:
                raise ValueError("LDAPMessage without protocolOp")
            message_id = parts[0].as_int()
            op = parts[1]
            session.record_command(OP_NAMES.get(op.tag, f"OP-{op.tag:#x}"))
            if op.tag == UNBIND_REQUEST:
                break
            if op.tag == BIND_REQUEST:
                body = self._bind(session, op, state)
                await self._reply(writer, message_id, BIND_RESPONSE, body)
                if session.get_number_of_login_attempts() >= self.max_attempts:
                    break
            elif op.tag == SEARCH_REQUEST:
                await self._search(writer, message_id, op)
            elif op.tag == EXTENDED_REQUEST:
                await self._reply(
                    writer, message_id, EXTENDED_RESPONSE, ldap_result(UNWILLING_TO_PERFORM)
                )
            elif op.tag in RESULT_RESPONSES:
                await self._reply(
                    writer, message_id, RESULT_RESPONSES[op.tag], ldap_result(INSUFFICIENT_ACCESS)
                )
            # abandon and unknown operations get no answer
        if state["sasl"]:
            session.set_auxiliary_data({"sasl_mechanisms": state["sasl"]})
        session.end_session()

    @staticmethod
    def _active_directory():
        persona = HandlerBase.persona
        return persona is not None and persona.os_family == "windows"

    def _result(self, code, **kwargs):
        if code == INVALID_CREDENTIALS and self._active_directory():
            kwargs.setdefault("diagnostic", AD_INVALID_CREDENTIALS)
        return ldap_result(code, **kwargs)

    def _bind(self, session, op, state):
        fields = op.children()
        if len(fields) < 3:
            raise ValueError("short BindRequest")
        name = decode_lossless(fields[1].value)
        auth = fields[2]
        if auth.tag == 0x80:  # simple
            password = decode_lossless(auth.value)
            if not name and not password:
                return self._result(SUCCESS)  # anonymous bind, needed for the RootDSE search
            session.add_auth_attempt("plaintext", username=name, password=password)
            return self._result(INVALID_CREDENTIALS)
        if auth.tag in (SICILY_DISCOVERY, SICILY_NEGOTIATE, SICILY_RESPONSE):
            if not self._active_directory():
                return self._result(AUTH_METHOD_NOT_SUPPORTED)
            if auth.tag == SICILY_DISCOVERY:
                return self._result(SUCCESS, matched_dn="NTLM")
            # the NTLM token travels in the bind and, for the challenge, in matchedDN
            reply = self._ntlm_step(session, auth.value, state)
            if reply is None:
                return self._result(INVALID_CREDENTIALS)
            return self._result(SUCCESS, matched_dn=reply)
        if auth.tag == 0xA3:  # sasl
            sasl_fields = auth.children()
            mechanism = decode_lossless(sasl_fields[0].value) if sasl_fields else ""
            if len(state["sasl"]) < MAX_SASL_RECORDS:
                state["sasl"].append(mechanism)
            if mechanism.upper() == "PLAIN" and len(sasl_fields) > 1:
                parts = sasl_fields[1].value.split(b"\x00")
                if len(parts) == 3:
                    session.add_auth_attempt(
                        "sasl-plain",
                        username=decode_lossless(parts[1] or parts[0]),
                        password=decode_lossless(parts[2]),
                    )
                    return self._result(INVALID_CREDENTIALS)
            if (
                mechanism.upper() == "GSS-SPNEGO"
                and len(sasl_fields) > 1
                and self._active_directory()
                and ntlm.SIGNATURE in sasl_fields[1].value
            ):
                reply = self._ntlm_step(session, sasl_fields[1].value, state)
                if reply is not None:
                    return self._result(SASL_BIND_IN_PROGRESS) + ber.octet_string(
                        reply, tag=SERVER_SASL_CREDS
                    )
                return self._result(INVALID_CREDENTIALS)
            # an advertised mechanism must not be "unsupported"; the bind just fails
            if mechanism.upper() in self._rootdse()["supportedSASLMechanisms"]:
                return self._result(INVALID_CREDENTIALS)
            return self._result(AUTH_METHOD_NOT_SUPPORTED)
        return self._result(AUTH_METHOD_NOT_SUPPORTED)

    def _ntlm_step(self, session, token, state):
        """NTLM negotiate -> challenge token (returned); authenticate -> logged, None."""
        message = ntlm.extract_message(token)
        kind = struct.unpack_from("<I", message, 8)[0]
        if kind == 1:
            persona = HandlerBase.persona
            state["challenge"] = secrets.token_bytes(8)
            challenge = ntlm.challenge_message(
                state["challenge"],
                persona.netbios or persona.hostname,
                persona.domain,
                persona.fqdn,
                version=ntlm.parse_version(persona.os_version),
            )
            # SPNEGO-wrapped requests get a wrapped answer, raw NTLM a raw one
            return challenge if token.startswith(ntlm.SIGNATURE) else ntlm.response_token(challenge)
        if kind == 3 and state["challenge"] is not None:
            username, domain, workstation, method, password_hash = ntlm.authenticate(
                message, state["challenge"]
            )
            state["challenge"] = None
            session.set_auxiliary_data({"domain": domain, "workstation": workstation})
            session.add_auth_attempt(
                method,
                username=f"{domain}\\{username}" if domain else username,
                password_hash=password_hash,
            )
            return None
        raise ValueError("unexpected NTLM message")

    async def _search(self, writer, message_id, op):
        fields = op.children()
        base = decode_lossless(fields[0].value) if fields else ""
        scope = fields[1].as_int() if len(fields) > 1 else 0
        if base != "" or scope != 0:
            await self._reply(
                writer, message_id, SEARCH_RESULT_DONE, ldap_result(INSUFFICIENT_ACCESS)
            )
            return
        wanted = set()
        if len(fields) >= 8 and fields[7].constructed:
            wanted = {decode_lossless(a.value).lower() for a in fields[7].children()}
        attrs = []
        for name, values in self._rootdse().items():
            if wanted and name.lower() not in wanted and "*" not in wanted and "+" not in wanted:
                continue
            attrs.append(
                ber.sequence(
                    ber.octet_string(name), ber.set_of(*(ber.octet_string(v) for v in values))
                )
            )
        entry = ber.octet_string("") + ber.sequence(*attrs)
        await self._reply(writer, message_id, SEARCH_RESULT_ENTRY, entry)
        await self._reply(writer, message_id, SEARCH_RESULT_DONE, ldap_result(SUCCESS))

    def _rootdse(self):
        naming = self.persona_value("naming_context", "dc=example,dc=com")
        vendor = self.persona_value("vendor_name", "OpenLDAP")
        attrs = {
            "objectClass": ["top", "OpenLDAProotDSE"],
            "namingContexts": [naming],
            "supportedLDAPVersion": ["3"],
            "supportedSASLMechanisms": ["PLAIN", "DIGEST-MD5", "GSSAPI"],
            "supportedControl": ["1.2.840.113556.1.4.319"],
        }
        if vendor != "OpenLDAP":  # OpenLDAP publishes neither vendor attributes nor a default
            attrs["objectClass"] = ["top"]
            attrs["vendorName"] = [vendor]
            attrs["vendorVersion"] = [self.persona_value("vendor_version", "")]
            attrs["defaultNamingContext"] = [naming]
        persona = HandlerBase.persona
        if persona is not None and persona.os_family == "windows":
            # Active Directory has no vendor attributes either
            attrs.pop("vendorName", None)
            attrs.pop("vendorVersion", None)
            attrs["defaultNamingContext"] = [naming]
            attrs["objectClass"] = ["top"]
            attrs["supportedCapabilities"] = ["1.2.840.113556.1.4.800"]
            attrs["dnsHostName"] = [persona.fqdn]
            attrs["rootDomainNamingContext"] = [naming]
            attrs["configurationNamingContext"] = ["CN=Configuration," + naming]
            attrs["schemaNamingContext"] = ["CN=Schema,CN=Configuration," + naming]
            attrs["supportedSASLMechanisms"] = ["GSSAPI", "GSS-SPNEGO", "EXTERNAL", "DIGEST-MD5"]
        return attrs

    @staticmethod
    async def _reply(writer, message_id, tag, body):
        writer.write(ber.sequence(ber.integer(message_id), ber.encode(tag, body)))
        await writer.drain()

    @staticmethod
    async def _read_message(reader):
        """Read one BER element (the LDAPMessage SEQUENCE) from the stream; None on EOF."""
        head = await reader.read(1)
        if not head:
            return None
        if head != b"\x30":
            raise ValueError("expected LDAPMessage SEQUENCE")
        first = await reader.readexactly(1)
        if first[0] < 0x80:
            length, length_bytes = first[0], b""
        else:
            count = first[0] & 0x7F
            if count == 0 or count > 4:
                raise ValueError("unsupported length")
            length_bytes = await reader.readexactly(count)
            length = int.from_bytes(length_bytes, "big")
        if length > ber.MAX_MESSAGE:
            raise ValueError("LDAPMessage too large")
        body = await reader.readexactly(length)
        return head + first + length_bytes + body

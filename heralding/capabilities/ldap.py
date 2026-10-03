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

from heralding.capabilities.handlerbase import HandlerBase
from heralding.libs import ber
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

SUCCESS, AUTH_METHOD_NOT_SUPPORTED, INVALID_CREDENTIALS = 0, 7, 49
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
        sasl = []
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
                code = self._bind(session, op, sasl)
                await self._reply(writer, message_id, BIND_RESPONSE, ldap_result(code))
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
        if sasl:
            session.set_auxiliary_data({"sasl_mechanisms": sasl})
        session.end_session()

    def _bind(self, session, op, sasl):
        fields = op.children()
        if len(fields) < 3:
            raise ValueError("short BindRequest")
        name = decode_lossless(fields[1].value)
        auth = fields[2]
        if auth.tag == 0x80:  # simple
            password = decode_lossless(auth.value)
            if not name and not password:
                return SUCCESS  # anonymous bind, needed for the RootDSE search
            session.add_auth_attempt("plaintext", username=name, password=password)
            return INVALID_CREDENTIALS
        if auth.tag == 0xA3:  # sasl
            sasl_fields = auth.children()
            mechanism = decode_lossless(sasl_fields[0].value) if sasl_fields else ""
            if len(sasl) < MAX_SASL_RECORDS:
                sasl.append(mechanism)
            if mechanism.upper() == "PLAIN" and len(sasl_fields) > 1:
                parts = sasl_fields[1].value.split(b"\x00")
                if len(parts) == 3:
                    session.add_auth_attempt(
                        "sasl-plain",
                        username=decode_lossless(parts[1] or parts[0]),
                        password=decode_lossless(parts[2]),
                    )
                    return INVALID_CREDENTIALS
            # an advertised mechanism must not be "unsupported"; the bind just fails
            if mechanism.upper() in self._rootdse()["supportedSASLMechanisms"]:
                return INVALID_CREDENTIALS
            return AUTH_METHOD_NOT_SUPPORTED
        return AUTH_METHOD_NOT_SUPPORTED

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

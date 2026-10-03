# Copyright (C) 2017 Johnny Vestergaard <jkv@unixcluster.dk>
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

import base64
import binascii
import logging

from heralding.capabilities.handlerbase import HandlerBase
from heralding.misc.textutil import decode_lossless

logger = logging.getLogger(__name__)

CRLF = "\r\n"
DEFAULT_CAPABILITIES = "IMAP4rev1 ID LITERAL+ AUTH=PLAIN AUTH=LOGIN"
EXCHANGE_CAPABILITIES = (
    "IMAP4 IMAP4rev1 AUTH=PLAIN UIDPLUS MOVE ID UNSELECT CHILDREN IDLE NAMESPACE LITERAL+"
)


def capabilities_for(banner: str) -> str:
    """The CAPABILITY list must match what the greeting advertises, as on a real server."""
    start = banner.find("[CAPABILITY ")
    end = banner.find("]", start)
    if start != -1 and end != -1:
        return banner[start + len("[CAPABILITY ") : end]
    if "Microsoft Exchange" in banner:
        return EXCHANGE_CAPABILITIES
    return DEFAULT_CAPABILITIES


class Imap(HandlerBase):
    NAME = "imap"

    def __init__(self, options):
        super().__init__(options)
        self.max_tries = int(self.options["protocol_specific_data"]["max_attempts"])
        self.banner = self.persona_value("banner", "* OK IMAP4rev1 Server Ready")

        self.capabilities = capabilities_for(self.banner)
        self.dovecot = "Dovecot" in self.banner
        self.available_commands = ["authenticate", "capability", "id", "login", "logout", "noop"]
        self.available_mechanisms = ["plain", "login"]

    async def execute_capability(self, reader, writer, session):
        await self._handle_session(session, reader, writer)

    async def _handle_session(
        self,
        session,
        reader,
        writer,
    ):
        await self.send_message(writer, self.banner)

        state = "Not Authenticated"
        while state != "Logout" and session.connected:
            # An exception is raised inside await reader.readline() in case of
            # sudden connection reset.
            raw_msg = await reader.readline()
            if not raw_msg:
                break

            raw_msg_str = raw_msg.decode("utf-8", "surrogateescape")
            session.record_command(decode_lossless(raw_msg).rstrip("\r\n"))

            cmd_msg = raw_msg_str.rstrip("\r\n").split(" ", 2)
            if len(cmd_msg) == 0:
                continue
            elif len(cmd_msg) == 1:
                await self.send_message(writer, "* BAD invalid command")
                continue
            elif len(cmd_msg) == 2:
                tag = cmd_msg[0]
                cmd = cmd_msg[1]
                args = ""
            else:
                tag = cmd_msg[0]
                cmd = cmd_msg[1]
                args = cmd_msg[2]

            cmd = cmd.lower()
            if cmd not in self.available_commands:
                await self.send_message(writer, tag + " BAD invalid command")
            else:
                func_to_call = getattr(self, f"cmd_{cmd}", None)
                if func_to_call:
                    return_value = await func_to_call(session, reader, writer, tag, args)
                    state = return_value
                else:
                    await self.send_message(writer, tag + " BAD invalid command")
        session.end_session()

    async def cmd_authenticate(self, session, reader, writer, tag, args):
        parts = args.split(None, 1)
        if not parts:
            await self.send_message(writer, tag + " BAD invalid command")
            return "Not Authenticated"
        auth_mechanism = parts[0].lower()
        if auth_mechanism not in self.available_mechanisms:
            await self.send_message(writer, tag + " BAD invalid command")
            return "Not Authenticated"

        if len(parts) == 2:
            # SASL-IR (RFC 4959): initial response on the command line, "=" means empty
            raw_msg = b"" if parts[1] == "=" else parts[1].encode("ascii", "replace")
        elif auth_mechanism == "login":
            raw_msg = None
        else:
            # the space after '+' is needed according to RFC
            await self.send_message(writer, "+ ")
            raw_msg = (await reader.readline()).rstrip(b"\r\n")

        if auth_mechanism == "login":
            values = []
            for prompt, initial in (("VXNlcm5hbWU6", raw_msg), ("UGFzc3dvcmQ6", None)):
                if initial is None:
                    await self.send_message(writer, "+ " + prompt)
                    initial = (await reader.readline()).rstrip(b"\r\n")
                success, value = self.try_b64decode(initial, session)
                if not success:
                    await self.send_message(writer, tag + " BAD invalid command")
                    return "Not Authenticated"
                values.append(decode_lossless(value))
            session.add_auth_attempt("plaintext", username=values[0], password=values[1])
            await self.send_message(writer, tag + self.auth_failed())
        elif auth_mechanism == "plain":
            success, credentials = self.try_b64decode(raw_msg, session)
            # \x00 separates authorization identity, username and password; the
            # authorization identity is unused here, so exactly two \x00 are expected (RFC 4616)
            if success and credentials.count(b"\x00") == 2:
                _, user, password = credentials.split(b"\x00")
                session.add_auth_attempt(
                    "plaintext", username=decode_lossless(user), password=decode_lossless(password)
                )
                await self.send_message(writer, tag + self.auth_failed())
            else:
                await self.send_message(writer, tag + " BAD invalid command")
        self.stop_if_too_many_attempts(session)
        return "Not Authenticated"

    def auth_failed(self):
        if self.dovecot:
            return " NO [AUTHENTICATIONFAILED] Authentication failed."
        return " NO Authentication failed"

    async def cmd_capability(self, session, reader, writer, tag, args):
        await self.send_message(writer, "* CAPABILITY " + self.capabilities)
        await self.send_message(writer, tag + " OK CAPABILITY completed")
        return "Not Authenticated"

    async def cmd_id(self, session, reader, writer, tag, args):
        await self.send_message(writer, '* ID ("name" "Dovecot")' if self.dovecot else "* ID NIL")
        await self.send_message(writer, tag + " OK ID completed")
        return "Not Authenticated"

    async def cmd_login(self, session, reader, writer, tag, args):
        try:
            values = await self._parse_astrings(reader, writer, args, 2)
        except ValueError:
            await self.send_message(writer, tag + " BAD invalid command")
            return "Not Authenticated"
        if not values:
            await self.send_message(writer, tag + " BAD invalid command")
            return "Not Authenticated"
        user = values[0]
        password = values[1] if len(values) > 1 else ""

        session.add_auth_attempt("plaintext", username=user, password=password)
        await self.send_message(writer, tag + self.auth_failed())
        self.stop_if_too_many_attempts(session)
        return "Not Authenticated"

    async def _parse_astrings(self, reader, writer, text, count):
        """Parse up to `count` IMAP astrings (atom, quoted string or {n} literal)."""
        values = []
        rest = text
        while len(values) < count:
            rest = rest.lstrip(" ")
            if not rest:
                break
            if rest.startswith('"'):
                value, rest = self._read_quoted(rest)
            elif rest.startswith("{") and rest.endswith("}"):
                size = int(rest[1:-1].rstrip("+"))
                if not 0 <= size <= 4096:
                    raise ValueError("literal too large")
                if not rest.endswith("+}"):  # non-synchronising literals need no go-ahead
                    await self.send_message(writer, "+ ")
                data = await reader.readexactly(size)
                value = decode_lossless(data)
                rest = decode_lossless(await reader.readline()).rstrip("\r\n")
            else:
                value, _, rest = rest.partition(" ")
            values.append(decode_lossless(value.encode("utf-8", "surrogateescape")))
        return values

    @staticmethod
    def _read_quoted(text):
        out = []
        i = 1
        while i < len(text):
            ch = text[i]
            if ch == "\\" and i + 1 < len(text):
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                return "".join(out), text[i + 1 :]
            out.append(ch)
            i += 1
        raise ValueError("unterminated quoted string")

    async def cmd_logout(self, session, reader, writer, tag, args):
        await self.send_message(writer, "* BYE IMAP4rev1 Server logging out")
        await self.send_message(writer, tag + " OK LOGOUT completed")
        return "Logout"

    async def cmd_noop(self, session, reader, writer, tag, args):
        await self.send_message(writer, tag + " OK NOOP completed")
        return "Not Authenticated"

    def stop_if_too_many_attempts(self, session):
        if session.get_number_of_login_attempts() >= self.max_tries:
            session.end_session()

    @staticmethod
    async def send_message(writer, msg):
        message_bytes = bytes(msg + CRLF, "utf-8")
        writer.write(message_bytes)
        await writer.drain()

    @staticmethod
    def try_b64decode(b64_str, session):
        try:
            return True, base64.b64decode(b64_str, validate=True)
        except binascii.Error, ValueError:
            logger.debug("Error decoding base64: %s (%s)", binascii.hexlify(b64_str), session.id)
            return False, b""

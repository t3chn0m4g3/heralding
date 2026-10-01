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

import logging

from heralding.capabilities.handlerbase import HandlerBase
from heralding.misc.textutil import decode_lossless

logger = logging.getLogger(__name__)


class Pop3(HandlerBase):
    NAME = "pop3"

    def __init__(self, options):
        super().__init__(options)
        self.max_tries = int(self.options["protocol_specific_data"]["max_attempts"])
        self.banner = self.options["protocol_specific_data"]["banner"]

    async def execute_capability(self, reader, writer, session):
        await self._handle_session(session, reader, writer)

    async def _handle_session(self, session, reader, writer):
        await self.send_message(writer, self.banner)

        state = "AUTHORIZATION"
        while state != "" and session.connected:
            raw_msg = await reader.readline()
            if not raw_msg:
                break

            raw_msg_str = decode_lossless(raw_msg)

            session.activity()
            cmd_msg = raw_msg_str.rstrip().split(" ", 1)
            if len(cmd_msg) == 0:
                continue
            elif len(cmd_msg) == 1:
                cmd = cmd_msg[0]
                msg = ""
            else:
                cmd = cmd_msg[0]
                msg = cmd_msg[1]

            cmd = cmd.lower()

            if cmd not in ["user", "pass", "quit", "noop"]:
                await self.send_message(writer, "-ERR Unknown command")
            else:
                func_to_call = getattr(self, f"cmd_{cmd}", None)
                return_value = await func_to_call(session, reader, writer, msg)
                # state changers!
                if return_value is not None and (state == "AUTHORIZATION" or cmd == "quit"):
                    state = return_value

        session.end_session()

    # APOP mrose c4c9334bac560ecc979e58001b3e22fb
    # +OK mrose's maildrop has 2 messages (320 octets)
    def auth_apop(self, session, gsocket, msg):
        raise Exception("Not implemented yet!")

    # USER mrose
    # +OK User accepted
    # PASS tanstaaf
    # +OK Pass accepted
    # or: "-ERR Authentication failed."
    # or: "-ERR No username given."
    async def cmd_user(self, session, reader, writer, msg):
        session.vdata["USER"] = msg
        await self.send_message(writer, "+OK User accepted")
        return "AUTHORIZATION"

    async def cmd_pass(self, session, reader, writer, msg):
        if "USER" not in session.vdata:
            await self.send_message(writer, "-ERR No username given.")
        else:
            session.add_auth_attempt("plaintext", username=session.vdata["USER"], password=msg)
            await self.send_message(writer, "-ERR Authentication failed.")

        if "USER" in session.vdata:
            del session.vdata["USER"]
        if session.get_number_of_login_attempts() >= self.max_tries:
            return ""  # leaves the command loop; the session is closed by the caller
        return "AUTHORIZATION"

    async def cmd_noop(self, session, reader, writer, msg):
        await self.send_message(writer, "+OK")
        return "AUTHORIZATION"

    async def cmd_quit(self, session, reader, writer, msg):
        await self.send_message(writer, "+OK Logging out")
        return ""

    @staticmethod
    async def send_message(writer, msg):
        message_bytes = bytes(msg + "\n", "utf-8")
        writer.write(message_bytes)
        await writer.drain()

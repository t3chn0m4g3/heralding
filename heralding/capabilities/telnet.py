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
from heralding.libs.telnetsrv.telnetsrvlib import TelnetHandlerBase
from heralding.misc.textutil import decode_lossless

logger = logging.getLogger(__name__)


class Telnet(HandlerBase):
    NAME = "telnet"

    def __init__(self, options):
        super().__init__(options)
        self.max_tries = int(self.options["protocol_specific_data"]["max_attempts"])

    async def execute_capability(self, reader, writer, session):
        telnet_cap = TelnetWrapper(reader, writer, session, self.max_tries)
        await telnet_cap.run()


class TelnetWrapper(TelnetHandlerBase):
    """
    Wraps the telnetsrv module to fit the Honeypot architecture.
    """

    PROMPT = b"$ "
    TERM = "ansi"

    authNeedUser = True
    authNeedPass = True

    def __init__(self, reader, writer, session, max_tries=3):
        self.auth_count = 0
        self.max_tries = max_tries
        self.username = None
        self.session = session
        address = writer.get_extra_info("peername")
        super().__init__(reader, writer, address)

    async def authentication_ok(self):
        try:
            return await self._auth_loop()
        except EOFError:
            return False

    async def _auth_loop(self):
        while self.auth_count < self.max_tries:
            username = await self.readline(prompt=b"Username: ", use_history=False)
            self.session.record_command(decode_lossless(username))
            password = await self.readline(echo=False, prompt=b"Password: ", use_history=False)
            self.session.record_command(decode_lossless(password))
            self.session.add_auth_attempt(
                _type="plaintext",
                username=decode_lossless(username),
                password=decode_lossless(password),
            )
            if self.DOECHO:
                await self.write(b"\n")
            self.auth_count += 1
        await self.writeline(b"Username: ")  # It fixes a problem with Hydra bruteforcer.
        return False

    def session_end(self):
        self.session.end_session()

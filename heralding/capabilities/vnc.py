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

import asyncio
import logging
import os

import heralding.honeypot
from heralding.capabilities.handlerbase import HandlerBase
from heralding.libs.cracker.vnc import crack_hash

# VNC constants
RFB_VERSION = b"RFB 003.007\n"
AUTH_METHODS = b"\x01\x02"
VNC_AUTH = b"\x02"
AUTH_FAILED = b"\x00\x00\x00\x01"

logger = logging.getLogger(__name__)


class Vnc(HandlerBase):
    NAME = "vnc"

    def __init__(self, options):
        super().__init__(options)
        # at most two wordlist runs at a time in the thread pool; the rest wait
        self._crack_sem: asyncio.Semaphore | None = None

    async def execute_capability(self, reader, writer, session):
        await self._handle_session(reader, writer, session)

    async def _handle_session(self, reader, writer, session):
        writer.write(RFB_VERSION)
        await writer.drain()
        client_version = await reader.readexactly(len(RFB_VERSION))

        if client_version == RFB_VERSION:
            await self.security_handshake(reader, writer, session)
        else:
            session.end_session()

    async def security_handshake(self, reader, writer, session):
        writer.write(AUTH_METHODS)
        await writer.drain()
        sec_method = await reader.readexactly(1)

        if sec_method == VNC_AUTH:
            await self.do_vnc_authentication(reader, writer, session)
        else:
            session.end_session()

    async def do_vnc_authentication(self, reader, writer, session):
        challenge = os.urandom(16)
        writer.write(challenge)
        await writer.drain()

        client_response = await reader.readexactly(16)
        writer.write(AUTH_FAILED)
        await writer.drain()

        # John the Ripper "vnc" format
        password_hash = f"$vnc$*{challenge.hex().upper()}*{client_response.hex().upper()}"

        wordlist = heralding.honeypot.Honeypot.wordlist
        cracked = None
        if wordlist:
            async with self._semaphore():
                cracked = await asyncio.to_thread(crack_hash, challenge, client_response, wordlist)
        if cracked is not None:
            session.add_auth_attempt("cracked", password=cracked, password_hash=password_hash)
        else:
            session.add_auth_attempt("des_challenge", password_hash=password_hash)

        session.end_session()

    def _semaphore(self) -> asyncio.Semaphore:
        if self._crack_sem is None:
            self._crack_sem = asyncio.Semaphore(2)
        return self._crack_sem

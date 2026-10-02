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

"""Redis capability: speaks enough RESP to collect AUTH/HELLO credentials.

Every other command is answered with NOAUTH; nothing is ever executed.
"""

import logging

from heralding.capabilities.handlerbase import HandlerBase
from heralding.misc.textutil import decode_lossless

logger = logging.getLogger(__name__)

MAX_ARGS = 64
MAX_ARG_LEN = 4096
MAX_LINE = 8192

WRONGPASS = b"-WRONGPASS invalid username-password pair or user is disabled.\r\n"
NOAUTH = b"-NOAUTH Authentication required.\r\n"
SYNTAX = b"-ERR syntax error\r\n"


class Redis(HandlerBase):
    NAME = "redis"

    async def execute_capability(self, reader, writer, session):
        while session.connected:
            args = await self._read_command(reader)
            if args is None:
                break
            if not args:
                continue
            command = decode_lossless(args[0]).upper()
            rest = [decode_lossless(a) for a in args[1:]]
            session.record_command(
                " ".join(
                    [command] + (["***"] * len(rest) if command in ("AUTH", "HELLO") else rest)
                )
            )
            if command == "AUTH":
                await self._auth(session, writer, rest)
            elif command == "HELLO":
                await self._hello(session, writer, rest)
            elif command == "QUIT":
                writer.write(b"+OK\r\n")
                await writer.drain()
                break
            else:
                writer.write(NOAUTH)
                await writer.drain()
        session.end_session()

    async def _auth(self, session, writer, rest):
        if len(rest) == 1:
            username, password = "default", rest[0]
        elif len(rest) == 2:
            username, password = rest
        else:
            writer.write(SYNTAX)
            await writer.drain()
            return
        session.add_auth_attempt("plaintext", username=username, password=password)
        writer.write(WRONGPASS)
        await writer.drain()

    async def _hello(self, session, writer, rest):
        # HELLO [protover [AUTH username password] [SETNAME clientname]]
        if "AUTH" in [r.upper() for r in rest]:
            idx = [r.upper() for r in rest].index("AUTH")
            if len(rest) >= idx + 3:
                session.add_auth_attempt(
                    "plaintext", username=rest[idx + 1], password=rest[idx + 2]
                )
                writer.write(WRONGPASS)
                await writer.drain()
                return
            writer.write(SYNTAX)
            await writer.drain()
            return
        writer.write(NOAUTH)
        await writer.drain()

    @staticmethod
    async def _read_command(reader):
        """Return the command as a list of bytes, [] for an empty line, None on EOF."""
        line = await reader.readline()
        if not line:
            return None
        if len(line) > MAX_LINE:
            raise ValueError("line too long")
        line = line.rstrip(b"\r\n")
        if not line.startswith(b"*"):
            return line.split()  # inline protocol
        count = int(line[1:])
        if count < 0 or count > MAX_ARGS:
            raise ValueError("bad multibulk count")
        args = []
        for _ in range(count):
            header = (await reader.readline()).rstrip(b"\r\n")
            if not header.startswith(b"$"):
                raise ValueError("expected bulk string")
            length = int(header[1:])
            if length < 0 or length > MAX_ARG_LEN:
                raise ValueError("bad bulk length")
            args.append(await reader.readexactly(length))
            await reader.readexactly(2)  # trailing CRLF
        return args

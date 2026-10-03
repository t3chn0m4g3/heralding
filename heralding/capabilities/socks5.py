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

# Socks constants
SOCKS_VERSION = b"\x05"
AUTH_METHOD = b"\x02"  # username/password authentication. RFC 1928
AUTH_VERSION = b"\x01"  # sub-negotiation version. RFC 1929
SOCKS_FAIL = b"\xff"

logger = logging.getLogger(__name__)


class Socks5(HandlerBase):
    NAME = "socks5"

    async def execute_capability(self, reader, writer, session):
        await self._handle_session(reader, writer, session)

    async def _handle_session(self, reader, writer, session):
        # greeting: VER NMETHODS METHODS... (RFC 1928)
        header = await reader.readexactly(2)
        version, nmethods = header[:1], header[1]
        authmethods = await reader.readexactly(nmethods)
        if version != SOCKS_VERSION:
            logger.debug("Wrong socks version: %r", version)
            session.end_session()
            return
        session.set_auxiliary_data(self.get_auxiliary_data(authmethods))
        if AUTH_METHOD[0] in authmethods:
            await self.do_authenticate(reader, writer, session)
        else:
            writer.write(SOCKS_VERSION + SOCKS_FAIL)
            await writer.drain()
        session.end_session()

    async def do_authenticate(self, reader, writer, session):
        writer.write(SOCKS_VERSION + AUTH_METHOD)
        await writer.drain()
        # sub-negotiation: VER ULEN UNAME PLEN PASSWD (RFC 1929); fields may arrive split
        _ver, ulen = await reader.readexactly(2)
        username = await reader.readexactly(ulen)
        plen = (await reader.readexactly(1))[0]
        password = await reader.readexactly(plen)
        session.add_auth_attempt(
            "plaintext", username=decode_lossless(username), password=decode_lossless(password)
        )
        writer.write(AUTH_VERSION + SOCKS_FAIL)
        await writer.drain()

    @staticmethod
    def get_auxiliary_data(authmethods):
        _methods = []
        for m in authmethods:
            if m == 2:
                _methods.append("USERNAME/PASSWORD")
            elif m == 0:
                _methods.append("NO AUTHENTICATION REQUIRED")
            elif m == 1:
                _methods.append("GSSAPI")
            elif 3 <= m <= 127:
                _methods.append(f"IANA ASSIGNED({hex(m)})")
            elif 128 <= m <= 254:
                _methods.append(f"PRIVATE METHOD({hex(m)})")
            elif m == 255:
                _methods.append("NO ACCEPTABLE METHODS")
        return {"client_auth_methods": _methods}

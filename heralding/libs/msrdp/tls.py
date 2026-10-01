# Copyright (C) 2019 Sudipta Pandit <realsdx@protonmail.com>
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

"""TLS over an existing asyncio stream (RDP upgrades the connection after the x224 negotiation).

Implemented with ``ssl.MemoryBIO`` so that the plaintext RDP PDUs can be read and written
through the same StreamReader/StreamWriter. Old mstsc clients still speak TLS 1.0, so the
minimum version is configurable and SECLEVEL is lowered to allow their cipher suites.
"""

import asyncio
import logging
import ssl

logger = logging.getLogger(__name__)

_CHUNK = 4096


class TLSHandshakeError(Exception):
    pass


class TLS:
    def __init__(self, writer, reader, pem_file, min_version="TLSv1"):
        self._in = ssl.MemoryBIO()
        self._out = ssl.MemoryBIO()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            ctx.minimum_version = getattr(ssl.TLSVersion, str(min_version))
        except AttributeError, ValueError:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        ctx.load_cert_chain(pem_file)
        self._ssl = ctx.wrap_bio(self._in, self._out, server_side=True)
        self.writer = writer
        self.reader = reader

    async def _flush(self):
        data = self._out.read()
        if data:
            self.writer.write(data)
            await self.writer.drain()

    async def _feed(self):
        chunk = await self.reader.read(_CHUNK)
        if not chunk:
            raise TLSHandshakeError("connection closed during TLS")
        self._in.write(chunk)

    async def do_tls_handshake(self):
        """Run the handshake; ClientHello and Finished may arrive in any number of reads."""
        while True:
            try:
                self._ssl.do_handshake()
            except ssl.SSLWantReadError:
                await self._flush()
                await self._feed()
                continue
            except ssl.SSLError as exc:
                await self._flush()  # deliver the alert, if any
                raise TLSHandshakeError(f"[{type(exc).__name__}] {exc.reason}") from None
            await self._flush()
            return

    @property
    def version(self) -> str:
        return self._ssl.version() or ""

    async def write_tls(self, data):
        self._ssl.write(data)
        await self._flush()

    async def read_tls(self, size):
        """Read exactly `size` plaintext bytes (IncompleteReadError on EOF)."""
        buf = b""
        while len(buf) < size:
            try:
                buf += self._ssl.read(size - len(buf))
            except ssl.SSLWantReadError:
                try:
                    await self._feed()
                except TLSHandshakeError:
                    raise asyncio.IncompleteReadError(buf, size) from None
            except ssl.SSLZeroReturnError:
                raise asyncio.IncompleteReadError(buf, size) from None
        return buf

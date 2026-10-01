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

# Parts of this code are from secure-smtpd (https://github.com/bcoe/secure-smtpd)

# Aniket Panse <contact@aniketpanse.in> grants Johnny Vestergaard <jkv@unixcluster.dk>
# a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable
# copyright license to reproduce, prepare derivative works of, publicly
# display, publicly perform, sublicense, relicense, and distribute [the] Contributions
# and such derivative works.

import base64
import binascii
import logging
import secrets
import time

from aiosmtpd.smtp import MISSING, SMTP, syntax

from heralding.capabilities.handlerbase import HandlerBase
from heralding.misc.textutil import decode_lossless

log = logging.getLogger(__name__)

DATA_SIZE_LIMIT = 1024 * 1024
AUTH_FAILED = "535 5.7.8 Authentication credentials invalid"
BAD_ENCODING = "501 5.5.2 Cannot decode response"


def set_fqdn(value: str) -> None:
    """Set the host name used in CRAM-MD5 challenges (called by Honeypot or from config)."""
    SMTPHandler.fqdn = value or ""


def _b64decode(blob) -> bytes:
    if isinstance(blob, str):
        blob = blob.encode("ascii", "replace")
    return base64.b64decode(blob.strip(), validate=True)


class SMTPHandler(SMTP):
    fqdn = ""

    def __init__(self, reader, writer, session, options, banner="ESMTP", ehlo_hostname=None):
        self.banner = banner
        self.ehlo_hostname = ehlo_hostname or banner
        super().__init__(None, hostname=self.banner, data_size_limit=DATA_SIZE_LIMIT)
        # Reset standard banner.
        self.__ident__ = ""
        self._reader = reader
        self._writer = writer
        self.transport = writer

        self._set_rset_state()
        self.session = session
        self.session.peer = self.transport.get_extra_info("peername")
        self.session.extended_smtp = None
        self.session.host_name = None

    async def push(self, status):
        response = bytes(status + "\r\n", "utf-8" if self.enable_SMTPUTF8 else "ascii")
        self._writer.write(response)
        log.debug(response)
        try:
            await self._writer.drain()
        except ConnectionResetError:
            self.stop()
        if self._reader.at_eof():
            self.stop()

    @syntax("EHLO hostname")
    async def smtp_EHLO(self, hostname):
        if not hostname:
            await self.push("501 Syntax: EHLO hostname")
            return
        self._set_rset_state()
        await self.push(f"250-{self.ehlo_hostname} Hello {hostname}")
        await self.push(f"250-SIZE {DATA_SIZE_LIMIT}")
        await self.push("250-8BITMIME")
        await self.push("250 AUTH PLAIN LOGIN CRAM-MD5")

    async def _read_auth_line(self):
        line = await self.readline()
        if not line:
            return None
        return line.strip()

    @syntax("AUTH mechanism [initial-response]")
    async def smtp_AUTH(self, arg):
        if not arg:
            await self.push("501 5.5.4 Syntax: AUTH mechanism [initial-response]")
            return
        args = arg.split()
        if len(args) > 2:
            await self.push("501 5.5.4 Too many values")
            return
        mechanism = args[0].upper()
        try:
            if mechanism == "PLAIN":
                await self._auth_plain(args)
            elif mechanism == "LOGIN":
                await self._auth_login(args)
            elif mechanism == "CRAM-MD5":
                await self._auth_cram_md5()
            else:
                await self.push("504 5.5.4 Unrecognized authentication type")
                return
        except binascii.Error, ValueError:
            await self.push(BAD_ENCODING)
            return
        if self.transport is not None:
            await self.push(AUTH_FAILED)

    async def _auth_plain(self, args):
        if len(args) == 1:
            await self.push("334 ")  # wait for client login/password
            blob = await self._read_auth_line()
            if blob is None:
                return
        else:
            blob = args[1]
        parts = _b64decode(blob).split(b"\x00")
        if len(parts) != 3:
            raise ValueError("PLAIN response needs two NUL separators")
        _, login, password = parts
        self.session.add_auth_attempt(
            "PLAIN", username=decode_lossless(login), password=decode_lossless(password)
        )

    async def _auth_login(self, args):
        if len(args) > 1:
            username = _b64decode(args[1])
        else:
            await self.push("334 " + base64.b64encode(b"Username:").decode())
            raw = await self._read_auth_line()
            if raw is None:
                return
            username = _b64decode(raw)
        await self.push("334 " + base64.b64encode(b"Password:").decode())
        raw = await self._read_auth_line()
        if raw is None:
            return
        password = _b64decode(raw)
        self.session.add_auth_attempt(
            "LOGIN", username=decode_lossless(username), password=decode_lossless(password)
        )

    async def _auth_cram_md5(self):
        # challenge is of the form '<24609.1047914046@awesome.host.com>'
        challenge = f"<{secrets.randbelow(15000) + 5000}.{int(time.time())}@{SMTPHandler.fqdn}>"
        challenge_bytes = challenge.encode("utf-8")
        await self.push("334 " + base64.b64encode(challenge_bytes).decode())

        raw = await self._read_auth_line()
        if raw is None:
            return
        response_raw = _b64decode(raw)
        response = decode_lossless(response_raw)
        if " " not in response:
            raise ValueError("CRAM-MD5 response needs 'user digest'")
        username, _digest = response.rsplit(" ", 1)
        # hashcat mode 10200: $cram_md5$<b64 challenge>$<b64 "user hexdigest">
        password_hash = f"$cram_md5${base64.b64encode(challenge_bytes).decode()}${base64.b64encode(response_raw).decode()}"
        self.session.add_auth_attempt("cram_md5", username=username, password_hash=password_hash)

    @syntax("QUIT")
    async def smtp_QUIT(self, arg):
        if arg:
            await self.push("501 Syntax: QUIT")
        else:
            status = await self._call_handler_hook("QUIT")
            await self.push("221 Bye" if status is MISSING else status)
            self.stop()

    async def readline(self):
        try:
            return await self._reader.readline()
        except ConnectionResetError:
            self.stop()
            return b""

    def stop(self):
        if self.transport is not None:
            self.transport.close()
        self.transport = None

    def _timeout_cb(self):
        if self.transport is not None:
            super()._timeout_cb()


class smtp(HandlerBase):
    NAME = "smtp"

    def __init__(self, options):
        super().__init__(options)
        self._options = options
        explicit_fqdn = options.get("protocol_specific_data", {}).get("fqdn")
        if explicit_fqdn:
            set_fqdn(explicit_fqdn)

    async def execute_capability(self, reader, writer, session):
        persona = HandlerBase.persona
        smtp_cap = SMTPHandler(
            reader,
            writer,
            session,
            self._options,
            banner=self.persona_value("banner", "ESMTP"),
            ehlo_hostname=persona.fqdn if persona is not None else None,
        )
        await smtp_cap._handle_client()

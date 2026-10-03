# Copyright (C) 2017 Johnny Vestergaard <jkv@unixcluster.dk>
#
# Rewritten by Aniket Panse <contact@aniketpanse.in>
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

# Aniket Panse <contact@aniketpanse.in> grants Johnny Vestergaard <jkv@unixcluster.dk>
# a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable
# copyright license to reproduce, prepare derivative works of, publicly
# display, publicly perform, sublicense, relicense, and distribute [the] Contributions
# and such derivative works.

import logging

from heralding.capabilities.handlerbase import HandlerBase
from heralding.misc.textutil import decode_lossless
from heralding.misc.tls import upgrade_stream

logger = logging.getLogger(__name__)

TERMINATOR = "\r\n"


class FtpHandler:
    """Handles a single FTP connection"""

    def __init__(
        self,
        reader,
        writer,
        options,
        session,
        banner="FTP Server",
        syst_type="UNIX Type: L8",
        tls_context=None,
    ):
        self.banner = banner
        self.max_loggins = int(options["protocol_specific_data"]["max_attempts"])
        self.syst_type = syst_type
        self.tls_context = tls_context  # None: AUTH TLS not offered (already on TLS, or disabled)
        self.tls_active = False
        self.authenticated = False
        self.writer = writer
        self.reader = reader
        self.serve_flag = True
        self.session = session

        self.state = None
        self.user = None

    async def getcmd(self):
        cmd = await self.reader.readline()
        return decode_lossless(cmd)

    async def serve(self):
        await self.respond("220 " + self.banner)

        while self.serve_flag:
            resp = await self.getcmd()
            if resp:
                self.session.record_command(resp.rstrip("\r\n"))
            if not resp:
                self.stop()
                break
            else:
                try:
                    cmd, args = resp.split(" ", 1)
                except ValueError:
                    cmd = resp
                    args = None
                else:
                    args = args.strip("\r\n")
                cmd = cmd.strip("\r\n")
                cmd = cmd.upper()
                # List of commands allowed before a login
                unauth_cmds = [
                    "USER",
                    "PASS",
                    "QUIT",
                    "SYST",
                    "FEAT",
                    "AUTH",
                    "PBSZ",
                    "PROT",
                    "OPTS",
                ]
                meth = getattr(self, "do_" + cmd, None)
                if not meth:
                    await self.respond("500 Unknown Command.")
                else:
                    if not self.authenticated:
                        if cmd not in unauth_cmds:
                            await self.respond("503 Login with USER first.")
                            continue
                    await meth(args)
                    self.state = cmd

    async def do_USER(self, arg):
        self.user = arg
        await self.respond("331 Now specify the Password.")

    async def do_PASS(self, arg):
        if self.state != "USER":
            await self.respond("503 Login with USER first.")
            return
        passwd = arg
        self.session.add_auth_attempt("plaintext", username=self.user, password=passwd)
        await self.respond("530 Authentication Failed.")
        if self.session.get_number_of_login_attempts() >= self.max_loggins:
            self.serve_flag = False
            self.stop()

    async def do_SYST(self, arg):
        await self.respond(f"215 {self.syst_type}")

    async def do_FEAT(self, arg):
        features = ["UTF8", "PBSZ", "PROT"]
        if self.tls_context is not None and not self.tls_active:
            features.insert(0, "AUTH TLS")
        await self.respond("211-Features:\r\n" + "".join(f" {f}\r\n" for f in features) + "211 End")

    async def do_AUTH(self, arg):
        # explicit FTPS (RFC 4217): AUTH TLS upgrades the control connection in place
        if self.tls_context is None or self.tls_active:
            await self.respond("502 Command not implemented.")
            return
        if (arg or "").upper() not in ("TLS", "TLS-C", "SSL"):
            await self.respond("504 Unknown security mechanism.")
            return
        await self.respond("234 AUTH TLS successful.")
        await upgrade_stream(self.reader, self.writer, self.tls_context)
        self.tls_active = True
        self.session.set_auxiliary_data({"starttls": True})

    async def do_PBSZ(self, arg):
        await self.respond("200 PBSZ=0")

    async def do_PROT(self, arg):
        await self.respond("200 Protection level set.")

    async def do_OPTS(self, arg):
        await self.respond("200 OK.")

    async def do_QUIT(self, arg):
        await self.respond("221 Bye.")
        self.serve_flag = False
        self.stop()

    async def respond(self, msg):
        msg += TERMINATOR
        msg_bytes = bytes(msg, "utf-8")
        self.writer.write(msg_bytes)
        await self.writer.drain()

    def stop(self):
        self.session.end_session()


class ftp(HandlerBase):
    NAME = "ftp"
    NEEDS_CERT = True  # for explicit AUTH TLS
    OFFER_AUTH_TLS = True

    def __init__(self, options):
        super().__init__(options)
        self._options = options

    async def execute_capability(self, reader, writer, session):
        if self.OFFER_AUTH_TLS:
            session.set_auxiliary_data({"starttls": False})
        ftp_cap = FtpHandler(
            reader,
            writer,
            self._options,
            session,
            banner=self.persona_value("banner", "FTP Server"),
            syst_type=self.persona_value("syst_type", "UNIX Type: L8"),
            tls_context=self.starttls_context if self.OFFER_AUTH_TLS else None,
        )
        await ftp_cap.serve()

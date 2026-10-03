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

# Reply texts of the server the banner names; "generic" for anything else.
DIALECTS = {
    "proftpd": {
        "user": "331 Password required for {user}",
        "fail": "530 Login incorrect.",
        "unknown": "500 {cmd} not understood",
        "login_first": "530 Please login with USER and PASS",
        "user_first": "503 Login with USER first",
        "auth_tls": "234 AUTH TLS successful",
        "pbsz": "200 PBSZ 0 successful",
        "prot": "200 Protection set to Private",
        "opts": "200 UTF8 set to on",
        "quit": "221 Goodbye.",
    },
    "vsftpd": {
        "user": "331 Please specify the password.",
        "fail": "530 Login incorrect.",
        "unknown": "500 Unknown command.",
        "login_first": "530 Please login with USER and PASS.",
        "user_first": "503 Login with USER first.",
        "auth_tls": "234 Proceed with negotiation.",
        "pbsz": "200 PBSZ set to 0.",
        "prot": "200 PROT now Private.",
        "opts": "200 Always in UTF8 mode.",
        "quit": "221 Goodbye.",
    },
    "microsoft": {
        "user": "331 Password required",
        "fail": "530 User cannot log in.",
        "unknown": "500 Command not understood.",
        "login_first": "530 Please login with USER and PASS.",
        "user_first": "503 Login with USER first.",
        "auth_tls": "234 AUTH command ok. Expecting TLS Negotiation.",
        "pbsz": "200 PBSZ command successful.",
        "prot": "200 PROT command successful.",
        "opts": "200 OPTS UTF8 command successful - UTF8 encoding now ON.",
        "quit": "221 Goodbye.",
    },
    "generic": {
        "user": "331 Now specify the Password.",
        "fail": "530 Authentication Failed.",
        "unknown": "500 Unknown Command.",
        "login_first": "503 Login with USER first.",
        "user_first": "503 Login with USER first.",
        "auth_tls": "234 AUTH TLS successful.",
        "pbsz": "200 PBSZ=0",
        "prot": "200 Protection level set.",
        "opts": "200 OK.",
        "quit": "221 Bye.",
    },
}


def dialect_for(banner: str) -> dict:
    lowered = banner.lower()
    for name in ("proftpd", "vsftpd", "microsoft"):
        if name in lowered:
            return DIALECTS[name]
    return DIALECTS["generic"]


def mapped_ip(ip: str) -> str:
    """Address as a dual-stack ProFTPD prints it: IPv4 in ::ffff: form."""
    return ip if ":" in ip else "::ffff:" + ip


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
        self.banner = banner.replace("{server_ip}", mapped_ip(str(session.destination_ip)))
        self.replies = dialect_for(banner)
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
                    await self.respond(self.replies["unknown"].replace("{cmd}", cmd[:64]))
                else:
                    if not self.authenticated:
                        if cmd not in unauth_cmds:
                            await self.respond(self.replies["login_first"])
                            continue
                    await meth(args)
                    self.state = cmd

    async def do_USER(self, arg):
        self.user = arg
        shown = "".join(ch for ch in (arg or "")[:64] if ch.isprintable())
        await self.respond(self.replies["user"].replace("{user}", shown))

    async def do_PASS(self, arg):
        if self.state != "USER":
            await self.respond(self.replies["user_first"])
            return
        passwd = arg
        self.session.add_auth_attempt("plaintext", username=self.user, password=passwd)
        await self.respond(self.replies["fail"])
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
        await self.respond(self.replies["auth_tls"])
        await upgrade_stream(self.reader, self.writer, self.tls_context)
        self.tls_active = True
        self.session.set_auxiliary_data({"starttls": True})

    async def do_PBSZ(self, arg):
        await self.respond(self.replies["pbsz"])

    async def do_PROT(self, arg):
        await self.respond(self.replies["prot"])

    async def do_OPTS(self, arg):
        await self.respond(self.replies["opts"])

    async def do_QUIT(self, arg):
        await self.respond(self.replies["quit"])
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

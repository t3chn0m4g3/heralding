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
import email.utils
import logging
import secrets
import time

from aiosmtpd.smtp import MISSING, SMTP, syntax

from heralding.capabilities.handlerbase import HandlerBase
from heralding.misc.textutil import decode_lossless
from heralding.misc.tls import upgrade_stream

log = logging.getLogger(__name__)

DATA_SIZE_LIMIT = 1024 * 1024

# Replies in the wording of the persona's mail server. aiosmtpd's own texts (the keys of
# "replace") would identify it, so push() translates them.
DIALECTS = {
    "postfix": {
        "ehlo_first": "250-{fqdn}",
        "features": [
            "PIPELINING",
            "SIZE 10240000",
            "ETRN",
            "ENHANCEDSTATUSCODES",
            "8BITMIME",
            "DSN",
        ],
        "auth": "AUTH PLAIN LOGIN CRAM-MD5",
        "auth_failed": "535 5.7.8 Error: authentication failed: authentication failure",
        "bad_encoding": "501 5.5.2 Cannot decode response",
        "bad_mechanism": "535 5.7.8 Error: authentication failed: Invalid authentication mechanism",
        "tls_ready": "220 2.0.0 Ready to start TLS",
        "unknown": "502 5.5.2 Error: command not recognized",
        "replace": {
            "250 OK": "250 2.0.0 Ok",
            "221 Bye": "221 2.0.0 Bye",
            "500 Error: bad syntax": "500 5.5.2 Error: bad syntax",
            "503 Error: send HELO first": "503 5.5.1 Error: send HELO/EHLO first",
            "503 Error: send EHLO first": "503 5.5.1 Error: send HELO/EHLO first",
            "503 Error: need MAIL command": "503 5.5.1 Error: need MAIL command",
            "503 Error: need RCPT command": "503 5.5.1 Error: need RCPT command",
            "503 Error: nested MAIL command": "503 5.5.1 Error: nested MAIL command",
            "502 EXPN not implemented": "502 5.5.2 Error: command not recognized",
            "500 Command line too long": "500 5.5.2 Error: line too long",
        },
        "help": "502 5.5.2 Error: command not recognized",
        "vrfy": "502 5.5.1 VRFY command is disabled",
    },
    "exchange": {
        "ehlo_first": "250-{fqdn} Hello [{peer}]",
        "features": ["SIZE 37748736", "PIPELINING", "DSN", "ENHANCEDSTATUSCODES", "8BITMIME"],
        "auth": "AUTH LOGIN",
        "auth_failed": "535 5.7.3 Authentication unsuccessful",
        "bad_encoding": "501 5.5.4 Invalid arguments",
        "bad_mechanism": "504 5.7.4 Unrecognized authentication type",
        "tls_ready": "220 2.0.0 SMTP server ready",
        "unknown": "500 5.3.3 Unrecognized command '{cmd}'",
        "replace": {
            "250 OK": "250 2.0.0 OK",
            "221 Bye": "221 2.0.0 Service closing transmission channel",
            "500 Error: bad syntax": "501 5.5.4 Invalid arguments",
            "503 Error: send HELO first": "503 5.5.2 Send hello first",
            "503 Error: send EHLO first": "503 5.5.2 Send hello first",
            "503 Error: need MAIL command": "503 5.5.2 Need mail command",
            "503 Error: need RCPT command": "503 5.5.2 Need rcpt command",
            "503 Error: nested MAIL command": "503 5.5.2 Sender already specified",
            "502 EXPN not implemented": "502 5.3.3 Command not implemented",
            "500 Command line too long": "500 5.3.3 Line too long",
        },
        "help": "214-This server supports the following commands:\r\n"
        "214 HELO EHLO STARTTLS RCPT DATA RSET MAIL QUIT HELP AUTH BDAT",
        "vrfy": "252 2.1.5 Cannot VRFY user",
    },
}


def dialect_for(banner: str) -> dict:
    return DIALECTS["exchange" if "Microsoft" in banner else "postfix"]


def set_fqdn(value: str, source: str = "persona") -> None:
    """Set the process-wide fallback host name used in CRAM-MD5 challenges.

    The persona value wins over the periodic DNS lookup; an explicit `fqdn` in a capability's
    config is handled per instance (see `smtp.__init__`) and beats both.
    """
    if source == "persona":
        SMTPHandler._fqdn_from_persona = bool(value)
        SMTPHandler.fqdn = value or ""
    elif source == "lookup":
        if not SMTPHandler._fqdn_from_persona:
            SMTPHandler.fqdn = value or ""
    else:
        raise ValueError(f"unknown fqdn source {source!r}")


def _b64decode(blob) -> bytes:
    if isinstance(blob, str):
        blob = blob.encode("ascii", "replace")
    return base64.b64decode(blob.strip(), validate=True)


class SMTPHandler(SMTP):
    fqdn = ""  # process-wide fallback (persona or lookup); see set_fqdn()
    _fqdn_from_persona = False

    def __init__(
        self,
        reader,
        writer,
        session,
        options,
        banner="ESMTP",
        ehlo_hostname=None,
        tls_context=None,
        fqdn=None,
    ):
        self.dialect = dialect_for(banner)
        if self.dialect is DIALECTS["exchange"] and banner.endswith("Service ready"):
            banner += " at " + email.utils.formatdate(localtime=True)
        self.banner = banner
        self.ehlo_hostname = ehlo_hostname or banner.split(" ", 1)[0]
        self.fqdn_value = fqdn or SMTPHandler.fqdn
        self._starttls_context = tls_context
        self._tls_active = False
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

    def _translate(self, status):
        if status.startswith('500 Error: command "'):
            return self.dialect["unknown"].replace("{cmd}", status.split('"')[1][:32])
        if status.startswith(("250 Supported commands", "250 Syntax: ")):
            return self.dialect["help"]
        if status.startswith("502 Could not VRFY"):
            return self.dialect["vrfy"]
        if status.startswith("220 ") and status.endswith(" "):
            return status.rstrip()  # aiosmtpd greeting with an empty ident
        return self.dialect["replace"].get(status, status)

    async def push(self, status):
        status = self._translate(status)
        response = bytes(status + "\r\n", "utf-8" if self.enable_SMTPUTF8 else "ascii")
        self._writer.write(response)
        log.debug(response)
        try:
            await self._writer.drain()
        except ConnectionResetError:
            self.stop()
        if self._reader.at_eof():
            self.stop()

    @syntax("HELO hostname")
    async def smtp_HELO(self, hostname):
        if not hostname:
            await self.push("501 Syntax: HELO hostname")
            return
        self._set_rset_state()
        self.session.extended_smtp = False
        self.session.host_name = hostname
        await self.push(f"250 {self.ehlo_hostname}")

    @syntax("EHLO hostname")
    async def smtp_EHLO(self, hostname):
        if not hostname:
            await self.push("501 Syntax: EHLO hostname")
            return
        self._set_rset_state()
        self.session.extended_smtp = True
        self.session.host_name = hostname
        peer = (self.session.peer or ("",))[0]
        first = self.dialect["ehlo_first"].replace("{fqdn}", self.ehlo_hostname)
        await self.push(first.replace("{peer}", str(peer)))
        features = list(self.dialect["features"])
        if self._starttls_context is not None and not self._tls_active:
            features.append("STARTTLS")
        features.append(self.dialect["auth"])
        for feature in features[:-1]:
            await self.push("250-" + feature)
        await self.push("250 " + features[-1])

    @syntax("STARTTLS")
    async def smtp_STARTTLS(self, arg):
        if arg:
            await self.push("501 Syntax: STARTTLS")
            return
        if self._starttls_context is None or self._tls_active:
            await self.push("454 4.7.0 TLS not available due to temporary reason")
            return
        await self.push(self.dialect["tls_ready"])
        # upgrade the existing stream in place; a failed handshake is a client error
        await upgrade_stream(self._reader, self._writer, self._starttls_context)
        self._tls_active = True
        self._set_rset_state()
        self.session.host_name = None
        self.session.set_auxiliary_data({"starttls": True})

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
                await self.push(self.dialect["bad_mechanism"])
                return
        except binascii.Error, ValueError:
            await self.push(self.dialect["bad_encoding"])
            return
        if self.transport is not None:
            await self.push(self.dialect["auth_failed"])

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
        challenge = f"<{secrets.randbelow(15000) + 5000}.{int(time.time())}@{self.fqdn_value}>"
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
    NEEDS_CERT = True  # for STARTTLS on port 25, as on a real MTA
    OFFER_AUTH_TLS = True

    def __init__(self, options):
        super().__init__(options)
        self._options = options
        self.explicit_fqdn = (options.get("protocol_specific_data") or {}).get("fqdn") or None

    async def execute_capability(self, reader, writer, session):
        persona = HandlerBase.persona
        if self.OFFER_AUTH_TLS:
            session.set_auxiliary_data({"starttls": False})
        smtp_cap = SMTPHandler(
            reader,
            writer,
            session,
            self._options,
            banner=self.persona_value("banner", "ESMTP"),
            ehlo_hostname=persona.fqdn if persona is not None else None,
            tls_context=self.starttls_context if self.OFFER_AUTH_TLS else None,
            fqdn=self.explicit_fqdn,
        )
        await smtp_cap._handle_client()

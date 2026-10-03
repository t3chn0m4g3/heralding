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

# Aniket Panse <contact@aniketpanse.in> grants Johnny Vestergaard <jkv@unixcluster.dk>
# a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable
# copyright license to reproduce, prepare derivative works of, publicly
# display, publicly perform, sublicense, relicense, and distribute [the] Contributions
# and such derivative works.

import base64
import binascii
import logging

from heralding.capabilities.handlerbase import HandlerBase
from heralding.libs.http.aioserver import AsyncBaseHTTPRequestHandler
from heralding.misc.textutil import decode_lossless

logger = logging.getLogger(__name__)

DEFAULT_SERVER_HEADER = "Microsoft-IIS/10.0"

# Error page templates in the style of the persona's web server family (no Python fingerprints).
ERROR_PAGE_IIS = (
    '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">\r\n'
    "<HTML><HEAD><TITLE>%(message)s</TITLE>\r\n"
    '<META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>\r\n'
    "<BODY><h2>%(message)s</h2>\r\n<hr><p>HTTP Error %(code)d. %(explain)s</p>\r\n</BODY></HTML>\r\n"
)
ERROR_PAGE_UNIX = (
    "<html>\r\n<head><title>%(code)d %(message)s</title></head>\r\n"
    "<body>\r\n<center><h1>%(code)d %(message)s</h1></center>\r\n"
    "<hr><center>%(server)s</center>\r\n</body>\r\n</html>\r\n"
)

HTTP_401_BODY = (
    b"<!DOCTYPE html><html><head><title>401 Unauthorized</title></head>"
    b"<body><h1>Unauthorized</h1><p>This server could not verify that you are authorized "
    b"to access the document requested.</p></body></html>"
)


def _is_iis_family(server_header: str, os_family: str | None) -> bool:
    """Pick the error page style from the advertised server; fall back to the persona's OS."""
    lowered = server_header.lower()
    if "iis" in lowered or "microsoft" in lowered:
        return True
    if any(name in lowered for name in ("nginx", "apache", "lighttpd", "openresty", "caddy")):
        return False
    return (os_family or "windows") == "windows"


class HTTPHandler(AsyncBaseHTTPRequestHandler):
    sys_version = ""  # never append "Python/x.y" to the Server header

    def __init__(self, reader, writer, httpsession, options, server_header=None, os_family=None):
        self.server_version = server_header or DEFAULT_SERVER_HEADER
        template = (
            ERROR_PAGE_IIS if _is_iis_family(self.server_version, os_family) else ERROR_PAGE_UNIX
        )
        self.error_message_format = template.replace(
            "%(server)s", self.server_version.replace("%", "%%")
        )
        self.error_content_type = "text/html"
        self._session = httpsession
        super().__init__(reader, writer, writer.get_extra_info("peername"))

    def version_string(self):
        return self.server_version

    def _send_401(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Restricted"')
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(HTTP_401_BODY)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(HTTP_401_BODY)
        self.close_connection = True

    def _handle_auth(self):
        self._session.set_auxiliary_data(self.get_auxiliary_info())
        header = self.headers.get("Authorization")
        if header is None:
            self._send_401()
            return
        scheme, _, blob = header.strip().partition(" ")
        if scheme.lower() != "basic" or not blob:
            self.send_error(400, "Bad Request")
            return
        try:
            decoded = decode_lossless(base64.b64decode(blob.strip(), validate=True))
        except binascii.Error, ValueError:
            self.send_error(400, "Bad Request")
            return
        username, _, password = decoded.partition(":")
        self._session.add_auth_attempt("plaintext", username=username, password=password)
        self._send_401()

    do_GET = do_POST = do_PUT = do_HEAD = do_OPTIONS = do_DELETE = do_PATCH = _handle_auth

    # Disable logging provided by BaseHTTPServer
    def log_message(self, format_, *args):
        pass

    def get_auxiliary_info(self):
        return {str(field): str(self.headers[str(field)]) for field in self.headers.keys()}


class Http(HandlerBase):
    NAME = "http"

    def __init__(self, options):
        super().__init__(options)
        self._options = options

    async def execute_capability(self, reader, writer, session):
        persona = HandlerBase.persona
        http_cap = HTTPHandler(
            reader,
            writer,
            httpsession=session,
            options=self._options,
            server_header=self.persona_value("banner", DEFAULT_SERVER_HEADER),
            os_family=persona.os_family if persona is not None else None,
        )
        await http_cap.run()
        session.end_session()

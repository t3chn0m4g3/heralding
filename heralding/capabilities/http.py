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

HTTP_401_BODY = (
    b"<!DOCTYPE html><html><head><title>401 Unauthorized</title></head>"
    b"<body><h1>Unauthorized</h1><p>This server could not verify that you are authorized "
    b"to access the document requested.</p></body></html>"
)


class HTTPHandler(AsyncBaseHTTPRequestHandler):
    sys_version = ""  # never append "Python/x.y" to the Server header

    def __init__(self, reader, writer, httpsession, options):
        psd = options.get("protocol_specific_data") or {}
        self.server_version = psd.get("banner") or DEFAULT_SERVER_HEADER
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
        http_cap = HTTPHandler(reader, writer, httpsession=session, options=self._options)
        await http_cap.run()
        session.end_session()

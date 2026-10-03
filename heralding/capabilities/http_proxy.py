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

"""HTTP proxy capability: demands Proxy-Authorization and never forwards anything."""

import base64
import binascii
import logging

from heralding.capabilities.handlerbase import HandlerBase
from heralding.capabilities.http import HTTPHandler
from heralding.misc.textutil import decode_lossless

logger = logging.getLogger(__name__)

DEFAULT_PROXY_HEADER = "squid/5.7"

HTTP_407_BODY = (
    b"<!DOCTYPE html><html><head><title>407 Proxy Authentication Required</title></head>"
    b"<body><h1>Proxy Authentication Required</h1><p>Please authenticate to use this proxy.</p>"
    b"</body></html>"
)


class ProxyRequestHandler(HTTPHandler):
    def _send_407(self):
        self.send_response(407)
        self.send_header("Proxy-Authenticate", 'Basic realm="proxy"')
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(HTTP_407_BODY)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(HTTP_407_BODY)
        self.close_connection = True

    def _handle_auth(self):
        aux = self.get_auxiliary_info()
        aux["method"] = self.command
        aux["target"] = self.path  # absolute URI for GET/POST, host:port for CONNECT
        self._session.set_auxiliary_data(aux)
        header = self.headers.get("Proxy-Authorization")
        if header is None:
            self._send_407()
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
        self._send_407()

    do_GET = do_POST = do_PUT = do_HEAD = do_OPTIONS = do_DELETE = do_PATCH = _handle_auth
    do_CONNECT = _handle_auth


class HttpProxy(HandlerBase):
    NAME = "http_proxy"

    def __init__(self, options):
        super().__init__(options)
        self._options = options

    async def execute_capability(self, reader, writer, session):
        persona = HandlerBase.persona
        handler = ProxyRequestHandler(
            reader,
            writer,
            httpsession=session,
            options=self._options,
            server_header=self.persona_value("banner", DEFAULT_PROXY_HEADER),
            os_family=persona.os_family if persona is not None else None,
        )
        await handler.run()
        session.end_session()

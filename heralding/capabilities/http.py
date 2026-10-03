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
import html
import logging
from http import HTTPStatus

from heralding.capabilities.handlerbase import HandlerBase
from heralding.libs.http.aioserver import AsyncBaseHTTPRequestHandler
from heralding.misc.textutil import decode_lossless

logger = logging.getLogger(__name__)

DEFAULT_SERVER_HEADER = "Microsoft-IIS/10.0"

# Response pages in the style of the persona's web server family (no Python fingerprints).
IIS_STYLE = """<!--
body{margin:0;font-size:.7em;font-family:Verdana, Arial, Helvetica, sans-serif;background:#EEEEEE;}
fieldset{padding:0 15px 10px 15px;}
h1{font-size:2.4em;margin:0;color:#FFF;}
h2{font-size:1.7em;margin:0;color:#CC0000;}
h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;}
#header{width:96%;margin:0 0 0 0;padding:6px 2% 6px 2%;font-family:"trebuchet MS", Verdana, sans-serif;color:#FFF;
background-color:#555555;}
#content{margin:0 0 0 2%;position:relative;}
.content-container{background:#FFF;width:96%;margin-top:8px;padding:10px;position:relative;}
-->"""
IIS_401 = (
    '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" '
    '"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">\r\n'
    '<html xmlns="http://www.w3.org/1999/xhtml">\r\n<head>\r\n'
    '<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>\r\n'
    "<title>401 - Unauthorized: Access is denied due to invalid credentials.</title>\r\n"
    '<style type="text/css">\r\n' + IIS_STYLE.replace("\n", "\r\n") + "\r\n</style>\r\n"
    '</head>\r\n<body>\r\n<div id="header"><h1>Server Error</h1></div>\r\n'
    '<div id="content">\r\n <div class="content-container"><fieldset>\r\n'
    "  <h2>401 - Unauthorized: Access is denied due to invalid credentials.</h2>\r\n"
    "  <h3>You do not have permission to view this directory or page using the credentials "
    "that you supplied.</h3>\r\n </fieldset></div>\r\n</div>\r\n</body>\r\n</html>\r\n"
)
# HTTP.sys answers malformed requests itself, before IIS sees them
IIS_ERROR = (
    '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">\r\n'
    "<HTML><HEAD><TITLE>{reason}</TITLE>\r\n"
    '<META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>\r\n'
    "<BODY><h2>{reason}</h2>\r\n<hr><p>HTTP Error {code}. {explain}</p>\r\n</BODY></HTML>\r\n"
)
IIS_EXPLAIN = {
    400: "The request is badly formed.",
    414: "The request URL is too long.",
    431: "The size of the request headers is too long.",
    501: "The request verb is invalid.",
    505: "The request has an invalid header name.",
}
NGINX_PAGE = (
    "<html>\r\n<head><title>{code} {title}</title></head>\r\n"
    "<body>\r\n<center><h1>{code} {title}</h1></center>\r\n"
    "<hr><center>{server}</center>\r\n</body>\r\n</html>\r\n"
)
NGINX_TITLES = {401: "Authorization Required", 414: "Request-URI Too Large"}
APACHE_PAGE = (
    '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n'
    "<title>{code} {reason}</title>\n</head><body>\n<h1>{reason}</h1>\n<p>{explain}</p>\n"
    "<hr>\n<address>{server} Server at {host} Port {port}</address>\n</body></html>\n"
)
APACHE_EXPLAIN = {
    400: "Your browser sent a request that this server could not understand.<br />\n",
    401: "This server could not verify that you\nare authorized to access the document\n"
    "requested.  Either you supplied the wrong\ncredentials (e.g., bad password), or your\n"
    "browser doesn't understand how to supply\nthe credentials required.",
    414: "The requested URL's length exceeds the capacity\nlimit for this server.<br />\n",
    431: "Your browser sent a request that this server could not understand.<br />\n"
    "Size of a request header field exceeds server limit.<br />\n",
    501: "{method} not supported for current URL.<br />\n",
}
REALMS = {"iis": "{host}", "apache": "Restricted Content", "nginx": "Restricted"}


def server_family(server_header: str, os_family: str | None) -> str:
    """'iis', 'apache' or 'nginx' (also used for other Unix servers), from the advertised
    server; falls back to the persona's OS."""
    lowered = server_header.lower()
    if "iis" in lowered or "microsoft" in lowered:
        return "iis"
    if "apache" in lowered:
        return "apache"
    if any(name in lowered for name in ("nginx", "lighttpd", "openresty", "caddy", "squid")):
        return "nginx"
    return "iis" if (os_family or "windows") == "windows" else "nginx"


class HTTPHandler(AsyncBaseHTTPRequestHandler):
    sys_version = ""  # never append "Python/x.y" to the Server header
    protocol_version = "HTTP/1.1"  # every response still closes the connection
    default_request_version = "HTTP/1.0"  # malformed request lines still get a status line

    def __init__(self, reader, writer, httpsession, options, server_header=None, os_family=None):
        self.server_version = server_header or DEFAULT_SERVER_HEADER
        self.family = server_family(self.server_version, os_family)
        persona = HandlerBase.persona
        sockname = writer.get_extra_info("sockname") or ("127.0.0.1", 80)
        self.server_host = persona.fqdn if persona is not None else str(sockname[0])
        self.server_port = sockname[1]
        self._session = httpsession
        super().__init__(reader, writer, writer.get_extra_info("peername"))

    def version_string(self):
        return self.server_version

    def _host(self):
        host = (self.headers.get("Host") if self.headers else None) or self.server_host
        return host.rsplit(":", 1)[0] if host.count(":") == 1 else host

    def _page(self, code, reason):
        if self.family == "iis":
            if code == 401:
                return IIS_401
            return IIS_ERROR.format(reason=reason, code=code, explain=IIS_EXPLAIN.get(code, ""))
        if self.family == "apache":
            explain = APACHE_EXPLAIN.get(code, "").replace(
                "{method}", html.escape(str(self.command))
            )
            return APACHE_PAGE.format(
                code=code,
                reason=reason,
                explain=explain,
                server=html.escape(self.server_version),
                host=html.escape(self._host()),
                port=self.server_port,
            )
        title = NGINX_TITLES.get(code, reason)
        return NGINX_PAGE.format(code=code, title=title, server=html.escape(self.server_version))

    def _send_page(self, code, extra_headers=()):
        reason = HTTPStatus(code).phrase
        body = self._page(code, reason).encode("latin-1", "replace")
        self.send_response(code, reason)
        for name, value in extra_headers:
            self.send_header(name, value)
        charset = "; charset=iso-8859-1" if self.family == "apache" else ""
        self.send_header("Content-Type", "text/html" + charset)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.close_connection = True

    def send_error(self, code, message=None, explain=None):
        """The reason phrase and page are the server family's, never the parser's message."""
        self._send_page(int(code))

    def _send_401(self):
        realm = REALMS[self.family].replace("{host}", self._host())
        self._send_page(401, [("WWW-Authenticate", f'Basic realm="{realm}"')])

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

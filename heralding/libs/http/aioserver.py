# We need this in order to reduce the number of third-party modules.
# The main idea is to replace rfile/wfile with reader/writer and to
# add async/await syntax. So, it is http.server.BaseHTTPRequestHandler
# code, but adjusted to work with asyncio in our specific case.

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from heralding.libs.aiobaserequest import AsyncBaseRequestHandler

from .aioclient import HeaderLimitExceeded, parse_headers

MAX_REQUEST_LINE = 8192


class AsyncBaseHTTPRequestHandler(AsyncBaseRequestHandler, BaseHTTPRequestHandler):
    """Asynchronous analogue of http.server.BaseHTTPRequestHandler.

    BaseHTTPRequestHandler.__init__ is never called (it would start handling
    synchronously); we only reuse its helper methods (send_response, send_header,
    end_headers, send_error, log_*). rfile/wfile come from AsyncBaseRequestHandler.
    """

    protocol_version = "HTTP/1.0"

    def __init__(self, reader, writer, client_address):
        AsyncBaseRequestHandler.__init__(self, reader, writer, client_address)
        self.headers = None
        self.command = None
        self.path = None
        self.request_version = self.default_request_version
        self.requestline = ""
        self.close_connection = True
        self._headers_buffer = []

    async def parse_request(self):
        self.command = None  # set in case of error on the first line
        self.request_version = version = self.default_request_version
        self.close_connection = True
        requestline = str(self.raw_requestline, "iso-8859-1")
        requestline = requestline.rstrip("\r\n")
        self.requestline = requestline
        words = requestline.split()
        if len(words) == 3:
            command, path, version = words
            if version[:5] != "HTTP/":
                self.send_error(
                    HTTPStatus.BAD_REQUEST, "Bad request version ({!r})".format(version)
                )
                return False
            try:
                base_version_number = version.split("/", 1)[1]
                version_number = base_version_number.split(".")
                if len(version_number) != 2:
                    raise ValueError
                version_number = int(version_number[0]), int(version_number[1])
            except ValueError, IndexError:
                self.send_error(
                    HTTPStatus.BAD_REQUEST, "Bad request version ({!r})".format(version)
                )
                return False
            if version_number >= (1, 1) and self.protocol_version >= "HTTP/1.1":
                self.close_connection = False
            if version_number >= (2, 0):
                self.send_error(
                    HTTPStatus.HTTP_VERSION_NOT_SUPPORTED,
                    "Invalid HTTP Version ({})".format(base_version_number),
                )
                return False
        elif len(words) == 2:
            command, path = words
            self.close_connection = True
            if command != "GET":
                self.send_error(
                    HTTPStatus.BAD_REQUEST, "Bad HTTP/0.9 request type ({!r})".format(command)
                )
                return False
        elif not words:
            return False
        else:
            self.send_error(HTTPStatus.BAD_REQUEST, "Bad request syntax ({!r})".format(requestline))
            return False
        self.command, self.path, self.request_version = command, path, version

        try:
            self.headers = await parse_headers(self.rfile, _class=self.MessageClass)
        except HeaderLimitExceeded as err:
            self.send_error(HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE, str(err))
            return False

        conntype = self.headers.get("Connection", "")
        if conntype.lower() == "close":
            self.close_connection = True
        elif conntype.lower() == "keep-alive" and self.protocol_version >= "HTTP/1.1":
            self.close_connection = False
        expect = self.headers.get("Expect", "")
        if (
            expect.lower() == "100-continue"
            and self.protocol_version >= "HTTP/1.1"
            and self.request_version >= "HTTP/1.1"
        ):
            if not self.handle_expect_100():
                return False
        return True

    async def handle_one_request(self):
        self.raw_requestline = await self.rfile.readline()
        if len(self.raw_requestline) > MAX_REQUEST_LINE:
            self.requestline = ""
            self.request_version = ""
            self.command = ""
            self.send_error(HTTPStatus.REQUEST_URI_TOO_LONG)
            self.close_connection = True
            return
        if not self.raw_requestline:
            self.close_connection = True
            return
        if not await self.parse_request():
            # An error code has been sent, just exit
            return
        mname = "do_" + self.command
        if not hasattr(self, mname):
            self.send_error(
                HTTPStatus.NOT_IMPLEMENTED, "Unsupported method ({!r})".format(self.command)
            )
            return
        method = getattr(self, mname)
        method()

    async def handle(self):
        self.close_connection = True

        await self.handle_one_request()
        while not self.close_connection:
            await self.handle_one_request()

# We need this in order to reduce the number of third-party modules.
# It is a part of code from http.client, that adjusted to work with
# asyncio in our specific case.

import email.parser
from http.client import HTTPMessage

MAX_HEADERS = 100
MAX_LINE = 8192


class HeaderLimitExceeded(Exception):
    pass


async def parse_headers(fp, _class=HTTPMessage):
    headers = []
    while True:
        line = await fp.readline()
        if len(line) > MAX_LINE:
            raise HeaderLimitExceeded("header line too long")
        headers.append(line)
        if len(headers) > MAX_HEADERS:
            raise HeaderLimitExceeded("too many headers")
        if line in (b"\r\n", b"\n", b""):
            break
    hstring = b"".join(headers).decode("iso-8859-1")
    return email.parser.Parser(_class=_class).parsestr(hstring)

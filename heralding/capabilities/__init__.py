"""All capability modules must be imported so that HandlerBase subclasses are registered."""

from heralding.capabilities import (  # noqa: F401
    ftp,
    http,
    https,
    imap,
    imaps,
    mysql,
    pop3,
    pop3s,
    postgresql,
    rdp,
    smtp,
    smtps,
    socks5,
    ssh,
    telnet,
    vnc,
)

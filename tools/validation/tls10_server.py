"""Manual FreeRDP fixture: force TLS 1.0 on the RDP listener only."""

import ssl
import warnings

from heralding.cli import main
from heralding.honeypot import Honeypot

original = Honeypot.create_ssl_context


def context(pem_file, min_version="TLSv1_2"):
    ctx = original(pem_file, min_version)
    if str(pem_file).endswith("rdp.pem"):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.maximum_version = ssl.TLSVersion.TLSv1
    return ctx


Honeypot.create_ssl_context = staticmethod(context)
main()

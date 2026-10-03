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

"""MSSQL (TDS) capability: PRELOGIN, LOGIN7 credentials logged, login refused.

Like SQL Server with its self-signed certificate, the server answers the client's encryption
wish: login-only TLS for ENCRYPT_OFF, a fully encrypted connection for ENCRYPT_ON/REQ and
plaintext for ENCRYPT_NOT_SUP. TDS 8 (TLS before PRELOGIN) is not supported.
"""

import logging
import ssl

from heralding.capabilities.handlerbase import HandlerBase
from heralding.libs import tds

logger = logging.getLogger(__name__)

DEFAULT_VERSION = "15.0.2000.5"


def _version_tuple(text):
    fields = str(text).split(".")
    if not 1 <= len(fields) <= 4:
        raise ValueError("MSSQL version must contain one to four numeric components")
    parts = [int(p) for p in fields]
    while len(parts) < 4:
        parts.append(0)
    major, minor, build, sub = parts
    if not (0 <= major <= 255 and 0 <= minor <= 255 and 0 <= build <= 65535 and 0 <= sub <= 65535):
        raise ValueError("MSSQL version component out of range")
    return major, minor, build, sub


class Mssql(HandlerBase):
    NAME = "mssql"
    NEEDS_CERT = True  # in-band TLS for the login, see module docstring
    OFFER_AUTH_TLS = True
    # SQL Server's own self-signed certificate carries nothing but this name
    CERT_SUBJECT = {"common_name": "SSL_Self_Signed_Fallback"}

    def __init__(self, options):
        super().__init__(options)
        self.version = _version_tuple(self.persona_value("version", DEFAULT_VERSION))

    def _tls_context(self):
        context = self.starttls_context
        if context is not None and context.minimum_version != ssl.TLSVersion.TLSv1_3:
            # TDS 7.x wraps the handshake in PRELOGIN packets; TLS 1.3 post-handshake
            # messages would not fit that, and SQL Server only uses TLS 1.3 with TDS 8
            context.maximum_version = ssl.TLSVersion.TLSv1_2
            return context
        return None

    async def execute_capability(self, reader, writer, session):
        packet_type, payload = await tds.read_packet(reader)
        if packet_type is None:
            session.end_session()
            return
        tls = None
        server_flag = tds.ENCRYPT_NOT_SUP
        if packet_type == tds.TYPE_PRELOGIN:
            options = tds.parse_prelogin(payload)
            encryption = options.get(tds.PRELOGIN_ENCRYPTION, b"")
            client_flag = encryption[0] if encryption else None
            context = self._tls_context()
            if context is not None:
                server_flag = tds.server_encryption(client_flag)
            session.set_auxiliary_data({"client_encryption": client_flag})
            writer.write(
                tds.packet(tds.TYPE_TABULAR, tds.build_prelogin(self.version, server_flag))
            )
            await writer.drain()
            if server_flag in (tds.ENCRYPT_OFF, tds.ENCRYPT_ON):
                tls = tds.TdsTls(context, reader, writer)
                await tls.handshake()
                session.set_auxiliary_data({"tls_version": tls.version})
                packet_type, payload = await tls.read_packet()
            else:
                packet_type, payload = await tds.read_packet(reader)
            if packet_type is None:
                session.end_session()
                return
        if packet_type != tds.TYPE_LOGIN7:
            raise ValueError(f"unexpected TDS packet type {packet_type:#x}")

        info = tds.parse_login7(payload)
        session.set_auxiliary_data(
            {
                "app_name": info["app_name"],
                "client_hostname": info["hostname"],
                "database": info["database"],
                "library": info["library"],
                "tds_version": info["tds_version"],
            }
        )
        session.add_auth_attempt("plaintext", username=info["username"], password=info["password"])
        persona = HandlerBase.persona
        server_name = persona.hostname if persona is not None else "MSSQLSERVER"
        response = tds.packet(
            tds.TYPE_TABULAR, tds.build_login_failed(info["username"], server_name)
        )
        if server_flag == tds.ENCRYPT_ON:
            await tls.write(response)
        else:  # plaintext, or login-only TLS that ended with LOGIN7
            writer.write(response)
            await writer.drain()
        session.end_session()

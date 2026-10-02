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

"""MSSQL (TDS) capability: PRELOGIN without encryption, LOGIN7 credentials logged, login refused.

Clients that insist on an encrypted login (e.g. ODBC Driver 18 defaults) disconnect after
PRELOGIN; that limitation is documented in docs/TPOT.md.
"""

import logging

from heralding.capabilities.handlerbase import HandlerBase
from heralding.libs import tds

logger = logging.getLogger(__name__)

DEFAULT_VERSION = "15.0.2000.5"


def _version_tuple(text):
    parts = [int(p) for p in str(text).split(".")[:4]]
    while len(parts) < 4:
        parts.append(0)
    major, minor, build, sub = parts
    return (major & 0xFF, minor & 0xFF, build & 0xFFFF, sub & 0xFFFF)


class Mssql(HandlerBase):
    NAME = "mssql"

    async def execute_capability(self, reader, writer, session):
        packet_type, payload = await tds.read_packet(reader)
        if packet_type is None:
            session.end_session()
            return
        if packet_type == tds.TYPE_PRELOGIN:
            options = tds.parse_prelogin(payload)
            encryption = options.get(tds.PRELOGIN_ENCRYPTION, b"")
            session.set_auxiliary_data({"client_encryption": encryption[0] if encryption else None})
            version = _version_tuple(self.persona_value("version", DEFAULT_VERSION))
            writer.write(tds.packet(tds.TYPE_TABULAR, tds.build_prelogin(version)))
            await writer.drain()
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
        writer.write(
            tds.packet(tds.TYPE_TABULAR, tds.build_login_failed(info["username"], server_name))
        )
        await writer.drain()
        session.end_session()

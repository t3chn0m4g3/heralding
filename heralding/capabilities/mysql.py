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

import logging
import os
import secrets
import struct

from heralding.capabilities.handlerbase import HandlerBase
from heralding.misc.textutil import decode_lossless

logger = logging.getLogger(__name__)

CLIENT_CONNECT_WITH_DB = 0x00000008
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_PLUGIN_AUTH = 0x00080000
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
MAX_PACKET = 0xFFFFFF

AUTH_PLUGIN = b"mysql_native_password"


def _int3(num):
    # MySQL protocol requires 3 byte integers for payload length
    return struct.pack("<I", num)[:3]


def _cstring(data, offset):
    end = data.index(b"\x00", offset)
    return data[offset:end], end + 1


def _lenenc(data, offset):
    first = data[offset]
    if first < 0xFB:
        return first, offset + 1
    if first == 0xFC:
        return int.from_bytes(data[offset + 1 : offset + 3], "little"), offset + 3
    if first == 0xFD:
        return int.from_bytes(data[offset + 1 : offset + 4], "little"), offset + 4
    return int.from_bytes(data[offset + 1 : offset + 9], "little"), offset + 9


# Implemented according to https://dev.mysql.com/doc/internals/en/connection-phase-packets.html
class MySQL(HandlerBase):
    NAME = "mysql"

    def __init__(self, options):
        super().__init__(options)
        self.PROTO_VER = b"\x0a"
        self.SERVER_VER = (
            self.persona_value("version", "5.7.16").encode("ascii", "replace") + b"\x00"
        )

    def server_greeting(self, salt):
        # Server Greeting (HandshakeV10): the 20-byte salt is split 8 + 12
        thread_id = struct.pack("<I", secrets.randbelow(2**31 - 1) + 1)
        salt_1 = salt[:8] + b"\x00"
        server_cap = b"\xff\xf7"
        server_lang = b"\x21"
        server_status = b"\x02\x00"
        ext_server_cap = b"\xff\x81"
        auth_plugin_len = bytes([len(AUTH_PLUGIN) + 1])
        zeros = bytes(0x0A)
        salt_2 = salt[8:20] + b"\x00"
        payload = (
            self.PROTO_VER
            + self.SERVER_VER
            + thread_id
            + salt_1
            + server_cap
            + server_lang
            + server_status
            + ext_server_cap
            + auth_plugin_len
            + zeros
            + salt_2
            + AUTH_PLUGIN
            + b"\x00"
        )
        return _int3(len(payload)) + b"\x00" + payload

    @staticmethod
    def auth_switch_request(seq_no, salt):
        # Ask clients using another method to switch to mysql_native_password
        payload = b"\xfe" + AUTH_PLUGIN + b"\x00" + salt + b"\x00"
        return _int3(len(payload)) + bytes([seq_no]) + payload

    @staticmethod
    def auth_failed(seq_no, user, server, using_password):
        # ERR packet, error 1045 (28000)
        error_msg = f"Access denied for user '{user}'@'{server}' (using password: {using_password})"
        payload = b"\xff" + b"\x15\x04" + b"#28000" + error_msg.encode("utf-8", "replace")
        return _int3(len(payload)) + bytes([seq_no]) + payload

    @staticmethod
    async def read_packet(reader):
        header = await reader.readexactly(4)
        length = int.from_bytes(header[:3], "little")
        if length > MAX_PACKET:
            raise ValueError("packet too large")
        return await reader.readexactly(length)

    async def execute_capability(self, reader, writer, session):
        await self._handle_session(reader, writer, session)

    async def _handle_session(self, reader, writer, session):
        address = writer.get_extra_info("peername")[0]
        salt = os.urandom(20)
        writer.write(self.server_greeting(salt))
        await writer.drain()

        payload = await self.read_packet(reader)
        if payload == b"\x01":  # COM_QUIT
            session.end_session()
            return
        if len(payload) < 32:
            raise ValueError("handshake response too short")

        # HandshakeResponse41: caps(4) max_packet(4) charset(1) reserved(23) user\0 auth ...
        caps = int.from_bytes(payload[0:4], "little")
        if not caps & CLIENT_PROTOCOL_41:
            logger.debug("MySQL client without CLIENT_PROTOCOL_41, ending session")
            session.end_session()
            return

        username_raw, offset = _cstring(payload, 32)
        username = decode_lossless(username_raw)
        if caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
            auth_len, offset = _lenenc(payload, offset)
        else:
            auth_len, offset = payload[offset], offset + 1
        scramble = payload[offset : offset + auth_len]
        offset += auth_len
        if caps & CLIENT_CONNECT_WITH_DB:
            _schema, offset = _cstring(payload, offset)

        seq_no = 2
        if caps & CLIENT_PLUGIN_AUTH:
            plugin, offset = _cstring(payload, offset)
            if plugin != AUTH_PLUGIN:
                salt = os.urandom(20)
                writer.write(self.auth_switch_request(seq_no, salt))
                await writer.drain()
                scramble = await self.read_packet(reader)
                seq_no = 4

        using_password = "YES" if scramble else "NO"
        if scramble:
            # hashcat mode 11200 (MySQL CRAM / mysql_native_password challenge-response)
            password_hash = f"$mysqlna${salt.hex()}*{scramble.hex()}"
        else:
            password_hash = None
        session.add_auth_attempt(
            "mysql_native_password", username=username, password="", password_hash=password_hash
        )
        writer.write(self.auth_failed(seq_no, username, address, using_password))
        await writer.drain()
        session.end_session()

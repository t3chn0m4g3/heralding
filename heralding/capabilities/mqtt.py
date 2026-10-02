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

"""MQTT capability: accepts one CONNECT packet, logs the credentials, refuses the session."""

import logging

from heralding.capabilities.handlerbase import HandlerBase
from heralding.misc.textutil import decode_lossless

logger = logging.getLogger(__name__)

MAX_REMAINING_LENGTH = 64 * 1024
CONNECT = 0x10
CONNACK = 0x20

# CONNACK return / reason codes
V3_BAD_CREDENTIALS = 0x04
V3_NOT_AUTHORIZED = 0x05
V5_BAD_CREDENTIALS = 0x86
V5_NOT_AUTHORIZED = 0x87


async def read_remaining_length(reader):
    """MQTT variable byte integer (1..4 bytes)."""
    multiplier = 1
    value = 0
    for _ in range(4):
        byte = (await reader.readexactly(1))[0]
        value += (byte & 0x7F) * multiplier
        if not byte & 0x80:
            return value
        multiplier *= 128
    raise ValueError("malformed remaining length")


def _read_string(data, pos):
    if pos + 2 > len(data):
        raise ValueError("truncated string length")
    length = int.from_bytes(data[pos : pos + 2], "big")
    end = pos + 2 + length
    if end > len(data):
        raise ValueError("truncated string")
    return data[pos + 2 : end], end


def _skip_properties(data, pos):
    """MQTT 5 properties: variable byte length prefix, then that many bytes."""
    multiplier = 1
    length = 0
    for _ in range(4):
        if pos >= len(data):
            raise ValueError("truncated properties")
        byte = data[pos]
        pos += 1
        length += (byte & 0x7F) * multiplier
        if not byte & 0x80:
            break
        multiplier *= 128
    return pos + length


class Mqtt(HandlerBase):
    NAME = "mqtt"

    async def execute_capability(self, reader, writer, session):
        header = await reader.readexactly(1)
        if header[0] & 0xF0 != CONNECT:
            raise ValueError("first packet is not CONNECT")
        remaining = await read_remaining_length(reader)
        if remaining > MAX_REMAINING_LENGTH:
            raise ValueError("CONNECT too large")
        data = await reader.readexactly(remaining)

        protocol_name, pos = _read_string(data, 0)
        if pos >= len(data):
            raise ValueError("truncated CONNECT")
        version = data[pos]
        flags = data[pos + 1] if pos + 1 < len(data) else 0
        pos += 4  # version, flags, keep alive (2)
        if version == 5:
            pos = _skip_properties(data, pos)
        client_id, pos = _read_string(data, pos)
        if flags & 0x04:  # will flag: will properties (v5), topic, payload
            if version == 5:
                pos = _skip_properties(data, pos)
            _, pos = _read_string(data, pos)
            _, pos = _read_string(data, pos)
        username = password = None
        if flags & 0x80:
            username, pos = _read_string(data, pos)
        if flags & 0x40:
            password, pos = _read_string(data, pos)

        session.set_auxiliary_data(
            {
                "client_id": decode_lossless(client_id),
                "mqtt_version": version,
                "protocol_name": decode_lossless(protocol_name),
            }
        )
        if username is not None or password is not None:
            session.add_auth_attempt(
                "plaintext",
                username=decode_lossless(username or b""),
                password=decode_lossless(password or b""),
            )
            code = V5_BAD_CREDENTIALS if version == 5 else V3_BAD_CREDENTIALS
        else:
            code = V5_NOT_AUTHORIZED if version == 5 else V3_NOT_AUTHORIZED

        if version == 5:
            # CONNACK: flags, reason code, empty properties
            writer.write(bytes([CONNACK, 3, 0x00, code, 0x00]))
        else:
            writer.write(bytes([CONNACK, 2, 0x00, code]))
        await writer.drain()
        session.end_session()

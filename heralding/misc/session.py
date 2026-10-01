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

import ipaddress
import json
import logging
import uuid
from datetime import UTC, datetime

from heralding.reporting.hub import get_hub

logger = logging.getLogger(__name__)


def normalize_ip(value):
    """Strip the IPv4-mapped IPv6 prefix (::ffff:a.b.c.d -> a.b.c.d); leave anything else as is."""
    try:
        addr = ipaddress.ip_address(str(value))
    except ValueError:
        return value
    mapped = getattr(addr, "ipv4_mapped", None)
    return str(mapped) if mapped is not None else str(addr)


class Session:
    def __init__(
        self, source_ip, source_port, protocol, users, destination_port=None, destination_ip=""
    ):

        self.id = uuid.uuid4()
        self.source_ip = normalize_ip(source_ip)
        self.source_port = source_port
        self.protocol = protocol
        import heralding.honeypot  # local import: honeypot imports the capabilities, which import us

        if heralding.honeypot.Honeypot.public_ip:
            self.destination_ip = heralding.honeypot.Honeypot.public_ip
        else:
            self.destination_ip = normalize_ip(destination_ip)
        self.destination_port = destination_port
        self.timestamp = datetime.now(UTC)
        self.num_ = 0
        self.session_ended = False
        # protocol specific data
        self.auxiliary_data = {}

        self.connected = True

        # for session specific volatile data (will not get logged)
        self.vdata = {}

        self.auth_attempts = []

        self.last_activity = datetime.now(UTC)
        self.log_start_session()

    def log_start_session(self):
        entry = self.get_session_info(False)
        get_hub().emit_session(entry)

    def activity(self):
        self.last_activity = datetime.now(UTC)

    def is_connected(self):
        return self.connected

    def get_auxiliary_data(self):
        return {}

    def get_number_of_login_attempts(self):
        return len(self.auth_attempts)

    def add_auth_attempt(self, _type, **kwargs):

        # constructs dict to transmitted right away.
        entry = {
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S.%f"),
            "session_id": str(self.id),
            "auth_id": str(uuid.uuid4()),
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "username": None,
            "password": None,
            "password_hash": None,
        }
        if "username" in kwargs:
            entry["username"] = kwargs["username"]
        if "password" in kwargs:
            entry["password"] = kwargs["password"]
        if "password_hash" in kwargs:
            entry["password_hash"] = kwargs["password_hash"]
        get_hub().emit_auth(entry)

        # add to internal dict used for reporting when the session ends
        self.auth_attempts.append(
            {
                "timestamp": entry["timestamp"],
                "username": entry["username"],
                "password": entry["password"],
                "auth_id": entry["auth_id"],
                "password_hash": entry["password_hash"],
                "method": _type,
            }
        )

        self.activity()
        logger.debug(
            "%s authentication attempt from %s:%s. Auth mechanism: %s, session id %s "
            "Credentials: %s",
            self.protocol,
            self.source_ip,
            self.source_port,
            _type,
            self.id,
            json.dumps(kwargs),
        )

    def get_session_info(self, session_ended):
        entry = {
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f"),
            "duration": int((datetime.now(UTC) - self.timestamp).total_seconds()),
            "session_id": str(self.id),
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "num_auth_attempts": len(self.auth_attempts),
            "auth_attempts": [dict(a) for a in self.auth_attempts],
            "session_ended": session_ended,
            "auxiliary_data": dict(self.auxiliary_data),
        }
        return entry

    MAX_COMMANDS = 50
    MAX_COMMAND_LEN = 256

    def set_auxiliary_data(self, data):
        """Merge protocol specific data into the session (keys from several sources coexist)."""
        self.auxiliary_data.update(data)

    def record_command(self, line):
        """Keep a bounded list of the client's command lines (auxiliary_data.commands)."""
        commands = self.auxiliary_data.setdefault("commands", [])
        if len(commands) >= self.MAX_COMMANDS:
            self.auxiliary_data["commands_truncated"] = True
            return
        commands.append(str(line)[: self.MAX_COMMAND_LEN])

    def end_session(self):
        if not self.session_ended:
            self.session_ended = True
            self.connected = False
            entry = self.get_session_info(True)

            get_hub().emit_session(entry)
            logger.debug("Session with session id %s ended", self.id)

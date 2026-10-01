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
import weakref

import asyncssh

from heralding.capabilities.handlerbase import HandlerBase

logger = logging.getLogger(__name__)


class SSH(asyncssh.SSHServer, HandlerBase):
    NAME = "ssh"
    # live connections only; entries disappear when asyncssh drops the connection object
    connections: weakref.WeakSet = weakref.WeakSet()

    def __init__(self, options):
        asyncssh.SSHServer.__init__(self)
        HandlerBase.__init__(self, options)
        self.session = None
        self.connection = None

    def connection_made(self, conn):
        SSH.connections.add(conn)
        self.connection = conn
        address = conn.get_extra_info("peername")
        dest_address = conn.get_extra_info("sockname")
        if self._limit_reached(address):
            conn.close()
            return
        self.session = self.create_session(address, dest_address)
        logger.debug("SSH connection received from %s.", address[0])

    def connection_lost(self, exc):
        if self.connection is not None:
            SSH.connections.discard(self.connection)
        if self.session is None:
            return
        self.session.set_auxiliary_data(self.get_auxiliary_data())
        self.close_session(self.session)
        if exc:
            logger.debug("SSH connection error [%s] %s", type(exc).__name__, exc)
        else:
            logger.debug("SSH connection closed.")

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        # asyncssh also routes keyboard-interactive "Password:" responses through here
        if self.session is not None:
            self.session.add_auth_attempt("plaintext", username=username, password=password)
        return False

    def get_auxiliary_data(self):
        data_fields = ["client_version", "recv_cipher", "recv_mac", "recv_compression"]
        return {f: self.connection.get_extra_info(f) for f in data_fields}

    async def create_server(self, bind_host, port, ssl_context=None):
        key_file = "ssh.key"
        self.generate_ssh_key(key_file)
        options = self.options
        banner = self.persona_value("banner", "SSH-2.0-OpenSSH_9.6")
        return await asyncssh.create_server(
            lambda: type(self)(options),
            bind_host,
            port,
            server_host_keys=[key_file],
            login_timeout=self.timeout,
            server_version=banner.removeprefix("SSH-2.0-"),
        )

    @staticmethod
    def generate_ssh_key(ssh_key_file):
        if os.path.isfile(ssh_key_file):
            return
        key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
        fd = os.open(ssh_key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key.export_private_key())

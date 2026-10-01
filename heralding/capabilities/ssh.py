# Copyright (C) 2017 Roman Samoilenko <ttahabatt@gmail.com>
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

import asyncssh
from Crypto.PublicKey import RSA

from heralding.capabilities.handlerbase import HandlerBase

logger = logging.getLogger(__name__)


class SSH(asyncssh.SSHServer, HandlerBase):
    NAME = "ssh"
    connections_list = []

    def __init__(self, options):
        asyncssh.SSHServer.__init__(self)
        HandlerBase.__init__(self, options)

    def connection_made(self, conn):
        SSH.connections_list.append(conn)
        self.address = conn.get_extra_info("peername")
        self.dest_address = conn.get_extra_info("sockname")
        self.connection = conn
        self.handle_connection()
        logger.debug("SSH connection received from {}.".format(conn.get_extra_info("peername")[0]))

    def connection_lost(self, exc):
        self.session.set_auxiliary_data(self.get_auxiliary_data())
        self.close_session(self.session)
        if exc:
            logger.debug("SSH connection error: " + str(exc))
        else:
            logger.debug("SSH connection closed.")

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        self.session.add_auth_attempt("plaintext", username=username, password=password)
        return False

    def handle_connection(self):
        if HandlerBase.global_sessions > HandlerBase.MAX_GLOBAL_SESSIONS:
            protocol = self.__class__.__name__.lower()
            logger.warning(
                "Got {} session on port {} from {}:{}, but not handling it because the global session limit has "
                "been reached".format(protocol, self.port, *self.address)
            )
        else:
            self.session = self.create_session(self.address, self.dest_address)

    def get_auxiliary_data(self):
        data_fields = ["client_version", "recv_cipher", "recv_mac", "recv_compression"]
        data = {f: self.connection.get_extra_info(f) for f in data_fields}
        return data

    async def create_server(self, bind_host, port, ssl_context=None):
        key_file = "ssh.key"
        self.generate_ssh_key(key_file)
        options = self.options
        banner = options["protocol_specific_data"]["banner"]
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
        if not os.path.isfile(ssh_key_file):
            with open(ssh_key_file, "w") as _file:
                rsa_key = RSA.generate(2048)
                priv_key_text = str(rsa_key.exportKey("PEM", pkcs=1), "utf-8")
                _file.write(priv_key_text)

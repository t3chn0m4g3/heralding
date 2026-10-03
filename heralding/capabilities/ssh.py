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

# Host keys and algorithm lists of a stock OpenSSH 9 server (asyncssh's own defaults differ and
# identify it). Algorithms asyncssh cannot provide are left out.
HOST_KEYS = (
    ("ssh.key", "ssh-rsa"),
    ("ssh_ecdsa.key", "ecdsa-sha2-nistp256"),
    ("ssh_ed25519.key", "ssh-ed25519"),
)
OPENSSH_KEX = (
    "mlkem768x25519-sha256",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group14-sha256",
)
OPENSSH_CIPHERS = (
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
)
OPENSSH_MACS = (
    "umac-64-etm@openssh.com",
    "umac-128-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",
    "umac-64@openssh.com",
    "umac-128@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1",
)
OPENSSH_HOST_KEY_ALGS = ("rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256", "ssh-ed25519")


def _available(wanted, supported):
    supported = {alg.decode() if isinstance(alg, bytes) else alg for alg in supported}
    return [alg for alg in wanted if alg in supported]


class SSH(asyncssh.SSHServer, HandlerBase):
    NAME = "ssh"
    # live connections only; entries disappear when asyncssh drops the connection object
    connections: weakref.WeakSet = weakref.WeakSet()

    def __init__(self, options):
        asyncssh.SSHServer.__init__(self)
        HandlerBase.__init__(self, options)
        self.session = None
        self.connection = None
        self._pubkeys = []

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

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        # Key attempts are not credentials: they go to auxiliary data, never to the authentication CSV
        if len(self._pubkeys) < 20:
            self._pubkeys.append(
                {
                    "username": username,
                    "key_type": key.get_algorithm(),
                    "fingerprint_sha256": key.get_fingerprint("sha256"),
                }
            )
        return False

    def validate_password(self, username, password):
        # asyncssh also routes keyboard-interactive "Password:" responses through here
        if self.session is not None:
            self.session.add_auth_attempt("plaintext", username=username, password=password)
        return False

    def get_auxiliary_data(self):
        data_fields = ["client_version", "recv_cipher", "recv_mac", "recv_compression"]
        data = {f: self.connection.get_extra_info(f) for f in data_fields}
        if self._pubkeys:
            data["publickey_attempts"] = list(self._pubkeys)
        return data

    async def create_server(self, bind_host, port, ssl_context=None):
        from asyncssh.encryption import get_encryption_algs
        from asyncssh.kex import get_kex_algs
        from asyncssh.mac import get_mac_algs

        for key_file, algorithm in HOST_KEYS:
            self.generate_ssh_key(key_file, algorithm)
        host_keys = asyncssh.load_keypairs([key_file for key_file, _ in HOST_KEYS])
        for keypair in host_keys:
            # OpenSSH 8.8+ offers neither ssh-rsa (SHA-1) nor the ssh.com RSA variants
            keypair.host_key_algorithms = [
                alg
                for name in OPENSSH_HOST_KEY_ALGS
                for alg in keypair.host_key_algorithms
                if alg.decode() == name
            ]
        options = self.options
        banner = self.persona_value("banner", "SSH-2.0-OpenSSH_9.6")
        return await asyncssh.create_server(
            lambda: type(self)(options),
            bind_host,
            port,
            server_host_keys=host_keys,
            kex_algs=_available(OPENSSH_KEX, get_kex_algs()),
            encryption_algs=_available(OPENSSH_CIPHERS, get_encryption_algs()),
            mac_algs=_available(OPENSSH_MACS, get_mac_algs()),
            compression_algs=["none", "zlib@openssh.com"],
            login_timeout=self.timeout,
            server_version=banner.removeprefix("SSH-2.0-"),
        )

    @staticmethod
    def generate_ssh_key(ssh_key_file, algorithm="ssh-rsa"):
        if os.path.isfile(ssh_key_file):
            return
        if algorithm == "ssh-rsa":
            key = asyncssh.generate_private_key(algorithm, key_size=3072)
        else:
            key = asyncssh.generate_private_key(algorithm)
        fd = os.open(ssh_key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key.export_private_key())

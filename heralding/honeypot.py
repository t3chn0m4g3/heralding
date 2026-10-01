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

import asyncio
import logging
import os
import socket
import ssl

import heralding.capabilities  # noqa: F401  registers all capabilities
import heralding.misc.common as common
from heralding.capabilities import smtp, ssh
from heralding.capabilities.handlerbase import HandlerBase
from heralding.misc import certs, persona
from heralding.reporting.hub import get_hub

logger = logging.getLogger(__name__)


class Honeypot:
    public_ip = ""
    wordlist = None

    def __init__(self, config):
        """
        :param config: configuration dictionary.
        """
        assert config is not None
        self.config = config
        self._servers = []
        self.public_ip_task = None
        self._fqdn_task = None
        self.persona = None

    async def _refresh_fqdn(self):
        while True:
            try:
                smtp.set_fqdn(await asyncio.to_thread(socket.getfqdn))
            except Exception as exc:
                logger.debug("getfqdn failed [%s] %s", type(exc).__name__, exc)
            await asyncio.sleep(1800)

    def _needs_fqdn_lookup(self) -> bool:
        for name in ("smtp", "smtps"):
            cfg = self.config["capabilities"].get(name) or {}
            if cfg.get("enabled") and not (cfg.get("protocol_specific_data") or {}).get("fqdn"):
                return True
        return False

    async def _record_and_lookup_public_ip(self):
        while True:
            try:
                Honeypot.public_ip = await asyncio.to_thread(common.get_public_ip)
                logger.info("Found public ip: %s", Honeypot.public_ip)
            except Exception as exc:
                Honeypot.public_ip = ""
                logger.warning("Could not determine public ip [%s] %s", type(exc).__name__, exc)
            await asyncio.sleep(3600)

    def setup_wordlist(self):
        # load wordlist in memory
        wordlist_file = self.config["hash_cracker"]["wordlist_file"]
        if not os.path.isfile(wordlist_file):
            package_directory = os.path.dirname(os.path.abspath(heralding.__file__))
            wordlist_file = os.path.join(package_directory, wordlist_file)
            logger.warning(
                f'Using default wordlist file: "{wordlist_file}", if you want to customize values please '
                "copy this file to the current working directory"
            )
        with open(wordlist_file) as f:
            Honeypot.wordlist = f.read().splitlines()

    async def start(self):
        """Starts services."""

        HandlerBase.configure_limits(
            self.config.get("max_sessions", 800), self.config.get("max_sessions_per_ip", 50)
        )
        self.persona = persona.select_persona(self.config)
        HandlerBase.set_persona(self.persona)
        logger.info("Persona: %s (%s)", self.persona.name, self.persona.fqdn)

        if self.config.get("public_ip_as_destination_ip") is True:
            self.public_ip_task = asyncio.create_task(self._record_and_lookup_public_ip())

        if self._needs_fqdn_lookup():
            self._fqdn_task = asyncio.create_task(self._refresh_fqdn())

        # setup hash cracker's wordlist
        if self.config["hash_cracker"]["enabled"]:
            self.setup_wordlist()

        bind_host = self.config["bind_host"]
        listen_ports = []
        for cap_name, cls in HandlerBase.registry().items():
            cap_cfg = self.config["capabilities"].get(cap_name)
            if not cap_cfg or not cap_cfg.get("enabled"):
                continue
            port = int(cap_cfg["port"])
            cap = cls(cap_cfg)
            ssl_context = None
            if cls.TLS == "implicit" or cls.NEEDS_CERT:
                psd = cap_cfg.get("protocol_specific_data") or {}
                pem_file = certs.ensure_cert(
                    f"{cap_name}.pem",
                    self._cert_subject(psd.get("cert")),
                    persona_tag=self.persona.name,
                )
                if cls.TLS == "implicit":
                    min_version = psd.get("tls_min_version") or self.config.get(
                        "tls_min_version", "TLSv1_2"
                    )
                    ssl_context = self.create_ssl_context(pem_file, min_version)
            try:
                server = await cap.create_server(bind_host, port, ssl_context)
            except OSError as exc:
                logger.error(
                    "Could not start %s on port %s [%s] %s",
                    cap_name,
                    port,
                    type(exc).__name__,
                    exc,
                )
                raise
            logger.debug("Adding %s capability with options: %s", cap_name, cap_cfg)
            self._servers.append(server)
            listen_ports.append(port)
            logger.info("Started %s capability listening on port %s", cap_name, port)
        get_hub().emit_listen_ports(listen_ports)

    async def stop(self):
        """Stops services"""
        for task in (self.public_ip_task, self._fqdn_task):
            if task is not None:
                task.cancel()

        for conn in list(ssh.SSH.connections):
            conn.close()
            try:
                await asyncio.wait_for(conn.wait_closed(), timeout=2)
            except TimeoutError:
                pass

        for server in self._servers:
            server.close()  # stop accepting
        for server in self._servers:
            server.close_clients()  # drop attackers still connected; sessions end normally
        for server in self._servers:
            try:
                await asyncio.wait_for(server.wait_closed(), timeout=5)
            except TimeoutError:
                logger.debug("Server on %s did not close in time", server.sockets)

        await common.cancel_all_pending_tasks()

        logger.info("All tasks were stopped.")

    def _cert_subject(self, cert_cfg):
        """Explicit certificate subject fields win; unset ones ("None", "", "*") come from the persona."""
        merged = dict(cert_cfg or {})
        for key, value in self.persona.cert_subject.items():
            current = merged.get(key)
            if certs.is_unset(current) or (key == "common_name" and current == "*"):
                if value:
                    merged[key] = value
        return merged

    @staticmethod
    def create_ssl_context(pem_file, min_version="TLSv1_2"):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.minimum_version = getattr(ssl.TLSVersion, str(min_version))
        ssl_context.load_cert_chain(pem_file)
        return ssl_context

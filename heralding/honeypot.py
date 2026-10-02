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
        self._datagram_transports = []
        self._capabilities = []
        self.public_ip_task = None
        self._fqdn_task = None
        self.persona = None

    async def _refresh_fqdn(self):
        while True:
            try:
                smtp.set_fqdn(await asyncio.to_thread(socket.getfqdn), source="lookup")
            except Exception as exc:
                logger.debug("getfqdn failed [%s] %s", type(exc).__name__, exc)
            await asyncio.sleep(1800)

    def _needs_fqdn_lookup(self) -> bool:
        if self.persona is not None:
            return False  # the persona owns the host name; never leak the real one
        for name in ("smtp", "smtps"):
            cfg = self.config["capabilities"].get(name) or {}
            if cfg.get("enabled") and not (cfg.get("protocol_specific_data") or {}).get("fqdn"):
                return True
        return False

    async def _lookup_public_ip_once(self):
        """Refresh Honeypot.public_ip; on failure keep the last good value."""
        try:
            Honeypot.public_ip = await asyncio.to_thread(common.get_public_ip)
            logger.info("Found public ip: %s", Honeypot.public_ip)
        except Exception as exc:
            logger.warning(
                "Could not determine public ip [%s] %s (keeping %r)",
                type(exc).__name__,
                exc,
                Honeypot.public_ip,
            )

    async def _record_and_lookup_public_ip(self):
        while True:
            await self._lookup_public_ip_once()
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
        self.persona = persona.select_persona(self.config, state_path="persona.state")
        HandlerBase.set_persona(self.persona)
        smtp.set_fqdn(self.persona.fqdn, source="persona")
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
            self._capabilities.append(cap)
            ssl_context = None
            if cls.TLS == "implicit" or (cls.NEEDS_CERT and cls.TLS != "starttls"):
                psd = cap_cfg.get("protocol_specific_data") or {}
                pem_file = certs.ensure_cert(
                    f"{cap_name}.pem",
                    self._cert_subject(psd.get("cert")),
                    persona_tag=self.persona.fqdn,
                )
                if cls.TLS == "implicit":
                    min_version = psd.get("tls_min_version") or self.config.get(
                        "tls_min_version", "TLSv1_2"
                    )
                    ssl_context = self.create_ssl_context(pem_file, min_version)
                elif cap_name == "rdp":
                    import warnings

                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", DeprecationWarning)
                        cap.tls_context = self.create_ssl_context(
                            pem_file, cap.persona_value("tls_min_version", "TLSv1")
                        )
                    cap.tls_context.set_ciphers("DEFAULT:@SECLEVEL=0")
            if cls.TLS == "starttls" or getattr(cls, "OFFER_AUTH_TLS", False):
                self._attach_starttls(cap, cap_name, cap_cfg)
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
            # Port zero is useful for collision-free local clients and tests.
            bound_ports = sorted({sock.getsockname()[1] for sock in server.sockets})
            listen_ports.extend(bound_ports)
            logger.info("Started %s capability listening on port %s", cap_name, bound_ports[0])
            if "udp" in cls.TRANSPORT:
                hosts = bind_host if isinstance(bind_host, list) else [bind_host]
                for host in hosts:
                    try:
                        transport, _ = await cap.create_datagram_endpoint(
                            host, port or bound_ports[0]
                        )
                    except OSError as exc:
                        logger.error(
                            "Could not start %s on udp port %s [%s] %s",
                            cap_name,
                            port,
                            type(exc).__name__,
                            exc,
                        )
                        raise
                    self._datagram_transports.append(transport)
                logger.info(
                    "Started %s capability listening on udp port %s",
                    cap_name,
                    port or bound_ports[0],
                )
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

        for cap in self._capabilities:
            if hasattr(cap, "close_datagram_sessions"):
                cap.close_datagram_sessions()
        for transport in self._datagram_transports:
            transport.close()
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

    def _attach_starttls(self, cap, cap_name, cap_cfg):
        """Build the in-band TLS context once; a broken certificate disables only the upgrade."""
        psd = cap_cfg.get("protocol_specific_data") or {}
        try:
            pem_file = certs.ensure_cert(
                f"{cap_name}.pem",
                self._cert_subject(psd.get("cert")),
                persona_tag=self.persona.fqdn,
            )
            min_version = psd.get("tls_min_version") or self.config.get(
                "tls_min_version", "TLSv1_2"
            )
            cap.starttls_context = self.create_ssl_context(pem_file, min_version)
        except (OSError, ValueError, AttributeError, ssl.SSLError) as exc:
            cap.starttls_context = None
            logger.warning(
                "%s: STARTTLS / AUTH TLS disabled, certificate not usable [%s] %s",
                cap_name,
                type(exc).__name__,
                exc,
            )

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
        from heralding.misc.tls import minimum_version

        ssl_context.minimum_version = minimum_version(min_version)
        ssl_context.load_cert_chain(pem_file)
        return ssl_context

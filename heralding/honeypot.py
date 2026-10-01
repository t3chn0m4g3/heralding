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
import ssl

import asyncssh

import heralding.capabilities.handlerbase
import heralding.misc.common as common
from heralding.reporting.curiosum_integration import CuriosumIntegration
from heralding.reporting.file_logger import FileLogger
from heralding.reporting.hpfeeds_logger import HpFeedsLogger
from heralding.reporting.reporting_relay import ReportingRelay
from heralding.reporting.syslog_logger import SyslogLogger

logger = logging.getLogger(__name__)


class Honeypot:
    public_ip = ""
    wordlist = None

    def __init__(self, config):
        """
        :param config: configuration dictionary.
        """
        assert config is not None
        self.SshClass = None
        self.config = config
        self._servers = []
        self._loggers = []
        self._logger_futures = []
        self.public_ip_task = None

    async def _record_and_lookup_public_ip(self):
        while True:
            try:
                Honeypot.public_ip = await asyncio.to_thread(common.get_public_ip)
                logger.warning("Found public ip: %s", Honeypot.public_ip)
            except Exception as ex:
                Honeypot.public_ip = ""
                logger.warning("Could not request public ip from ipify, error: %s", ex)
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

    def _start_logger(self, instance):
        loop = asyncio.get_running_loop()
        future = loop.run_in_executor(None, instance.start)
        future.add_done_callback(common.on_unhandled_task_exception)
        self._logger_futures.append(future)
        self._loggers.append(instance)

    async def start(self):
        """Starts services."""

        if self.config.get("public_ip_as_destination_ip") is True:
            self.public_ip_task = asyncio.create_task(self._record_and_lookup_public_ip())

        # setup hash cracker's wordlist
        if self.config["hash_cracker"]["enabled"]:
            self.setup_wordlist()

        # start activity logging
        activity = self.config.get("activity_logging") or {}
        if activity.get("file", {}).get("enabled"):
            file_cfg = activity["file"]
            self._start_logger(
                FileLogger(
                    file_cfg["session_csv_log_file"],
                    file_cfg["session_json_log_file"],
                    file_cfg["authentication_log_file"],
                )
            )
        if activity.get("syslog", {}).get("enabled"):
            self._start_logger(SyslogLogger())
        if activity.get("hpfeeds", {}).get("enabled"):
            hp = activity["hpfeeds"]
            self._start_logger(
                HpFeedsLogger(
                    hp["session_channel"],
                    hp["auth_channel"],
                    hp["host"],
                    hp["port"],
                    hp["ident"],
                    hp["secret"],
                )
            )
        if activity.get("curiosum", {}).get("enabled"):
            self._start_logger(CuriosumIntegration(activity["curiosum"]["port"]))

        bind_host = self.config["bind_host"]
        listen_ports = []
        for c in heralding.capabilities.handlerbase.HandlerBase.__subclasses__():
            cap_name = c.__name__.lower()
            if cap_name not in self.config["capabilities"]:
                continue
            if not self.config["capabilities"][cap_name]["enabled"]:
                continue
            port = self.config["capabilities"][cap_name]["port"]
            listen_ports.append(port)
            # carve out the options for this specific service
            options = self.config["capabilities"][cap_name]
            # capabilities are only allowed to append to the session list
            cap = c(options)
            try:
                # Convention: All capability names which end in 's' will be wrapped in ssl.
                if cap_name.endswith("s"):
                    pem_file = f"{cap_name}.pem"
                    self.create_cert_if_not_exists(cap_name, pem_file)
                    ssl_context = self.create_ssl_context(pem_file)
                    server = await asyncio.start_server(
                        cap.handle_session, bind_host, port, ssl=ssl_context
                    )
                elif cap_name == "ssh":
                    # Since dicts and user-defined classes are mutable, we have
                    # to save ssh class and ssh options somewhere.
                    ssh_options = options
                    SshClass = c
                    self.SshClass = SshClass

                    ssh_key_file = "ssh.key"
                    SshClass.generate_ssh_key(ssh_key_file)

                    banner = ssh_options["protocol_specific_data"]["banner"]
                    SshClass.change_server_banner(banner)

                    server = await asyncssh.create_server(
                        lambda: SshClass(ssh_options),  # noqa: B023
                        bind_host,
                        port,
                        server_host_keys=[ssh_key_file],
                        login_timeout=cap.timeout,
                    )
                elif cap_name == "rdp":
                    pem_file = f"{cap_name}.pem"
                    self.create_cert_if_not_exists(cap_name, pem_file)
                    server = await asyncio.start_server(cap.handle_session, bind_host, port)
                else:
                    server = await asyncio.start_server(cap.handle_session, bind_host, port)

                logger.debug("Adding %s capability with options: %s", cap_name, options)
                self._servers.append(server)
            except Exception as ex:
                logger.error(
                    "Could not start %s server on port %s [%s] %s",
                    c.__name__,
                    port,
                    type(ex).__name__,
                    ex,
                )
                raise
            else:
                logger.info("Started %s capability listening on port %s", c.__name__, port)
        ReportingRelay.logListenPorts(listen_ports)

    async def stop(self):
        """Stops services"""
        if self.public_ip_task is not None:
            self.public_ip_task.cancel()

        if self.SshClass is not None:
            for conn in list(self.SshClass.connections_list):
                conn.close()
                await conn.wait_closed()

        for server in self._servers:
            server.close()
            await server.wait_closed()

        for lg in self._loggers:
            lg.stop()

        await common.cancel_all_pending_tasks()

        logger.info("All tasks were stopped.")

    def create_cert_if_not_exists(self, cap_name, pem_file):
        if not os.path.isfile(pem_file):
            logger.debug("Generating certificate and key: %s", pem_file)

            cert_dict = self.config["capabilities"][cap_name]["protocol_specific_data"]["cert"]
            cert_cn = cert_dict["common_name"]
            cert_country = cert_dict["country"]
            cert_state = cert_dict["state"]
            cert_locality = cert_dict["locality"]
            cert_org = cert_dict["organization"]
            cert_org_unit = cert_dict["organizational_unit"]
            valid_days = int(cert_dict["valid_days"])
            serial_number = int(cert_dict["serial_number"])

            cert, key = common.generate_self_signed_cert(
                cert_country,
                cert_state,
                cert_org,
                cert_locality,
                cert_org_unit,
                cert_cn,
                valid_days,
                serial_number,
            )
            with open(pem_file, "wb") as _pem_file:
                _pem_file.write(cert)
                _pem_file.write(key)

    @staticmethod
    def create_ssl_context(pem_file):
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.check_hostname = False
        ssl_context.load_cert_chain(pem_file)
        return ssl_context

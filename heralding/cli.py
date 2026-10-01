#!/usr/bin/env python3
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
import grp
import logging
import logging.handlers
import os
import pwd
import signal
from argparse import ArgumentParser

import yaml

import heralding
import heralding.honeypot
from heralding.reporting.hub import build_hub, set_hub

logger = logging.getLogger()


def setup_logging(logfile, verbose):
    """
        Sets up logging to the logfiles/console.
    :param logfile: Path of the file to write logs to.
    :param verbose: If True, enables verbose logging.
    """
    root_logger = logging.getLogger()

    default_formatter = logging.Formatter("%(asctime)-15s (%(name)s) %(message)s")

    if verbose:
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO
    root_logger.setLevel(loglevel)

    console_log = logging.StreamHandler()
    console_log.setFormatter(default_formatter)
    console_log.setLevel(loglevel)
    root_logger.addHandler(console_log)

    if logfile in ("/dev/log", "/dev/syslog", "/var/run/syslog", "/var/run/log"):
        file_log = logging.handlers.SysLogHandler(address=logfile, facility="local1")
        syslog_formatter = logging.Formatter("heralding[%(process)d]: %(message)s")
        file_log.setFormatter(syslog_formatter)
    else:
        file_log = logging.FileHandler(logfile)
        file_log.setFormatter(default_formatter)
    file_log.setLevel(loglevel)
    root_logger.addHandler(file_log)

    # ensure the filer is applied to all handlers
    for handler in root_logger.handlers:
        handler.addFilter(LogFilter())


class LogFilter(logging.Filter):
    def filter(self, rec):
        """Filtering internal logs of aiosmtpd, asyncssh"""
        if rec.name == "asyncssh":
            if logging.getLogger().level == logging.DEBUG:
                return True
            if rec.levelno <= 20:
                return False
            else:
                return True

        if rec.name == "mail.log":
            return False
        else:
            return True


def drop_privileges(uid_name="nobody", gid_name="nogroup"):
    """Drops current privileges to the privileges of selected user."""
    if os.getuid() != 0:
        return

    wanted_uid = pwd.getpwnam(uid_name)[2]
    wanted_gid = grp.getgrnam(gid_name)[2]

    os.setgid(wanted_gid)
    os.setuid(wanted_uid)

    new_uid_name = pwd.getpwuid(os.getuid())[0]
    new_gid_name = grp.getgrgid(os.getgid())[0]

    logger.info("Privileges dropped, running as %s/%s.", new_uid_name, new_gid_name)


def load_config(config_file):
    if not os.path.isfile(config_file):
        package_directory = os.path.dirname(os.path.abspath(heralding.__file__))
        config_file = os.path.join(package_directory, config_file)
        logger.warning(
            'Using default config file: "%s", if you want to customize values please '
            "copy this file to the current working directory",
            config_file,
        )
    with open(config_file) as _file:
        return yaml.safe_load(_file.read())


async def main_async(config, stop_event: asyncio.Event | None = None) -> None:
    loop = asyncio.get_running_loop()
    stop_event = stop_event or asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_event.set)
    honeypot = heralding.honeypot.Honeypot(config)
    try:
        await honeypot.start()
    except Exception:
        logger.exception("Could not start honeypot")
        await honeypot.stop()
        raise SystemExit(1) from None
    drop_privileges()
    await stop_event.wait()
    logger.info("Shutdown requested")
    await honeypot.stop()


def main(argv=None) -> int:
    parser = ArgumentParser(description="Heralding")

    parser.add_argument(
        "-v", "--verbose", action="store_true", default=False, help="Logs debug messages."
    )
    parser.add_argument(
        "-l", "--logfile", dest="logfile", default="heralding.log", help="Heralding log file"
    )
    parser.add_argument(
        "-c", "--config", dest="config", default="heralding.yml", help="Heralding config file"
    )
    args = parser.parse_args(argv)

    setup_logging(args.logfile, args.verbose)

    logger.info("Initializing Heralding version %s", heralding.version)

    try:
        config = load_config(args.config)
    except Exception as ex:
        logger.error(
            "Error while reading config file %s [%s] %s", args.config, type(ex).__name__, ex
        )
        return 2

    hub = build_hub(config)
    set_hub(hub)
    hub.start()
    try:
        asyncio.run(main_async(config))
    except SystemExit as ex:
        return int(ex.code or 1)
    finally:
        hub.stop()
        set_hub(None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

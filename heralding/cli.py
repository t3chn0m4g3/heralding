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
import logging
import logging.handlers
import os
import signal
from argparse import ArgumentParser

import yaml

import heralding
import heralding.honeypot
from heralding.misc.privileges import drop_privileges
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


def loop_exception_handler(loop, context):
    """A peer that vanished while a library callback ran (e.g. asyncssh setting socket options
    on a reset connection) is a client error: debug log only, no traceback."""
    exc = context.get("exception")
    if isinstance(exc, OSError | EOFError):
        logger.debug(
            "Client error in event loop callback [%s] %s", type(exc).__name__, exc, exc_info=exc
        )
        return
    loop.default_exception_handler(context)


async def main_async(config, stop_event: asyncio.Event | None = None) -> None:
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(loop_exception_handler)
    stop_event = stop_event or asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_event.set)
    honeypot = heralding.honeypot.Honeypot(config)
    try:
        await honeypot.start()
    except Exception as exc:
        logger.error("Could not start honeypot [%s] %s", type(exc).__name__, exc)
        logger.debug("startup failure", exc_info=True)
        await honeypot.stop()
        raise SystemExit(1) from None
    drop_privileges(config.get("user", "nobody"), config.get("group", "nogroup"))
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

    try:
        hub = build_hub(config)
        hub.start()
    except Exception as exc:
        logger.error("Could not open log sink [%s] %s", type(exc).__name__, exc)
        logger.debug("sink startup failure", exc_info=True)
        return 2
    set_hub(hub)
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

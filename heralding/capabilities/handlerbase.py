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
import collections
import logging
import ssl
import time

from heralding.misc.session import Session

logger = logging.getLogger(__name__)

_WARN_INTERVAL = 60.0
# Errors a hostile or broken client can trigger at will. They are logged at DEBUG only.
_CLIENT_ERRORS = (
    ConnectionError,
    EOFError,
    asyncio.IncompleteReadError,
    asyncio.LimitOverrunError,
    ssl.SSLError,
    UnicodeError,
    ValueError,
    IndexError,
    KeyError,
    OSError,
)


class HandlerBase:
    NAME: str = ""  # protocol name as logged; part of the T-Pot contract for existing services
    TLS: str | None = None  # "implicit" | "starttls" | None
    TRANSPORT: str = "tcp"  # "tcp" | "udp"
    NEEDS_CERT: bool = False  # capability handles TLS itself but needs <NAME>.pem in CWD
    _registry: dict[str, type["HandlerBase"]] = {}

    max_sessions = 800
    max_sessions_per_ip = 50
    global_sessions = 0
    sessions_per_ip: collections.Counter = collections.Counter()
    _last_limit_warn = 0.0
    _last_error_warn = 0.0

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if cls.NAME:
            HandlerBase._registry[cls.NAME] = cls

    @classmethod
    def registry(cls) -> dict[str, type["HandlerBase"]]:
        return dict(cls._registry)

    @classmethod
    def configure_limits(cls, max_sessions: int, max_sessions_per_ip: int) -> None:
        HandlerBase.max_sessions = int(max_sessions)
        HandlerBase.max_sessions_per_ip = int(max_sessions_per_ip)

    def __init__(self, options):
        """
        Base class that all capabilities must inherit from.

        :param options: a dictionary of configuration options.
        """
        self.options = options
        self.sessions = {}
        self.users = {}
        self.port = int(options["port"])
        self.timeout = int(options.get("timeout", 30))

    async def create_server(self, bind_host, port, ssl_context: ssl.SSLContext | None = None):
        return await asyncio.start_server(
            self.handle_session,
            bind_host,
            port,
            ssl=ssl_context,
            limit=16 * 1024,
            ssl_handshake_timeout=self.timeout if ssl_context else None,
        )

    def create_session(self, address, dest_address):
        session = Session(
            address[0], address[1], self.NAME, self.users, dest_address[1], dest_address[0]
        )
        self.sessions[session.id] = session
        HandlerBase.global_sessions += 1
        HandlerBase.sessions_per_ip[address[0]] += 1
        logger.debug(
            "Accepted %s session on %s:%s from %s:%s. (%s)",
            self.NAME,
            dest_address[0],
            dest_address[1],
            address[0],
            address[1],
            session.id,
        )
        return session

    def close_session(self, session):
        logger.debug("Closing session. (%s)", session.id)
        session.end_session()
        if self.sessions.pop(session.id, None) is not None:
            HandlerBase.global_sessions -= 1
            ip = session.source_ip
            HandlerBase.sessions_per_ip[ip] -= 1
            if HandlerBase.sessions_per_ip[ip] <= 0:
                del HandlerBase.sessions_per_ip[ip]

    async def execute_capability(self, reader, writer, session):
        raise NotImplementedError

    def _limit_reached(self, address) -> bool:
        if HandlerBase.global_sessions >= HandlerBase.max_sessions:
            reason = "global session limit"
        elif HandlerBase.sessions_per_ip[address[0]] >= HandlerBase.max_sessions_per_ip:
            reason = "per-ip session limit"
        else:
            return False
        now = time.monotonic()
        if now - HandlerBase._last_limit_warn > _WARN_INTERVAL:
            HandlerBase._last_limit_warn = now
            logger.warning(
                "Rejecting %s session from %s:%s, %s reached",
                self.NAME,
                address[0],
                address[1],
                reason,
            )
        return True

    async def handle_session(self, reader, writer):
        address = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        dest_address = writer.get_extra_info("sockname") or ("0.0.0.0", self.port)
        if self._limit_reached(address):
            await self._close_writer(writer)
            return
        session = self.create_session(address, dest_address)
        try:
            await asyncio.wait_for(
                self.execute_capability(reader, writer, session), timeout=self.timeout
            )
        except TimeoutError:
            logger.debug("Session timed out. (%s)", session.id)
        except _CLIENT_ERRORS as exc:
            logger.debug(
                "Client error in %s session [%s] %s (%s)",
                self.NAME,
                type(exc).__name__,
                exc,
                session.id,
            )
        except Exception as exc:  # last line of defence: never let a traceback reach the log
            self._warn_error(exc, session)
        finally:
            self.close_session(session)
            await self._close_writer(writer)

    def _warn_error(self, exc, session):
        logger.debug("Unexpected error in %s session (%s)", self.NAME, session.id, exc_info=True)
        now = time.monotonic()
        if now - HandlerBase._last_error_warn > _WARN_INTERVAL:
            HandlerBase._last_error_warn = now
            logger.warning(
                "Unexpected error in %s session [%s] %s; see debug log for details",
                self.NAME,
                type(exc).__name__,
                str(exc).replace(":", " "),
            )

    @staticmethod
    async def _close_writer(writer):
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2)
        except OSError, TimeoutError, ssl.SSLError:
            pass

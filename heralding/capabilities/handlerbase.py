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
import ipaddress
import logging
import socket
import ssl
import struct
import time

from heralding.misc.session import Session, normalize_ip

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
    struct.error,
)


class HandlerBase:
    NAME: str = ""  # stable protocol name in the public log format
    TLS: str | None = None  # "implicit" | "starttls" | None
    TRANSPORT: str = "tcp"  # "tcp" | "udp"
    NEEDS_CERT: bool = False  # capability handles TLS itself but needs <NAME>.pem in CWD
    persona = None  # set by Honeypot.start(); see misc/persona.py
    starttls_context = None  # set by Honeypot.start() for STARTTLS / AUTH TLS capabilities
    PERSONA_NAME: str | None = (
        None  # persona entry to use when it differs from NAME (e.g. ftps -> ftp)
    )
    _registry: dict[str, type[HandlerBase]] = {}

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
    def registry(cls) -> dict[str, type[HandlerBase]]:
        return dict(cls._registry)

    @classmethod
    def set_persona(cls, persona) -> None:
        HandlerBase.persona = persona

    def persona_value(self, key: str, default=None):
        """Explicit, non-empty config value wins; then the persona; then the default."""
        explicit = (self.options.get("protocol_specific_data") or {}).get(key)
        if explicit not in (None, ""):
            return explicit
        if HandlerBase.persona is not None:
            value = HandlerBase.persona.get(self.PERSONA_NAME or self.NAME, key)
            if value is not None:
                return value
        return default

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
        HandlerBase.sessions_per_ip[session.source_ip] += 1
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
        elif (
            HandlerBase.sessions_per_ip[normalize_ip(address[0])] >= HandlerBase.max_sessions_per_ip
        ):
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


class DatagramHandlerBase(HandlerBase):
    """Base for UDP capabilities: one short-lived session per datagram source, a token bucket
    per source address and a reply size bound (anti-amplification)."""

    TRANSPORT = "udp"
    BUCKET_SIZE = 20  # replies allowed in a burst per source
    REFILL_PER_SECOND = 5.0
    MAX_SOURCES = 4096
    MAX_REPLY_RATIO = 3  # reply bytes <= ratio * request bytes
    GLOBAL_BUCKET_SIZE = 200
    GLOBAL_REFILL_PER_SECOND = 100.0

    def __init__(self, options):
        super().__init__(options)
        self._buckets = collections.OrderedDict()
        self._udp_sessions = {}
        self._idle_handles = {}
        self._global_bucket = (float(self.GLOBAL_BUCKET_SIZE), time.monotonic())

    async def create_datagram_endpoint(self, bind_host, port):
        loop = asyncio.get_running_loop()
        if ":" in str(bind_host):
            # asyncio sets IPV6_V6ONLY for TCP listeners but not for UDP; without it "::"
            # collides with a 0.0.0.0 endpoint on the same port (Linux)
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((bind_host, port))
                return await loop.create_datagram_endpoint(
                    lambda: _DatagramProtocol(self), sock=sock
                )
            except BaseException:
                sock.close()
                raise
        return await loop.create_datagram_endpoint(
            lambda: _DatagramProtocol(self), local_addr=(bind_host, port)
        )

    def _allow(self, source_ip: str) -> bool:
        now = time.monotonic()
        tokens, last = self._buckets.get(source_ip, (float(self.BUCKET_SIZE), now))
        tokens = min(self.BUCKET_SIZE, tokens + (now - last) * self.REFILL_PER_SECOND)
        if tokens < 1:
            self._buckets[source_ip] = (tokens, now)
            self._buckets.move_to_end(source_ip)
            return False
        if len(self._buckets) >= self.MAX_SOURCES and source_ip not in self._buckets:
            self._buckets.popitem(last=False)
        self._buckets[source_ip] = (tokens - 1, now)
        self._buckets.move_to_end(source_ip)
        global_tokens, global_last = self._global_bucket
        global_tokens = min(
            self.GLOBAL_BUCKET_SIZE,
            global_tokens + (now - global_last) * self.GLOBAL_REFILL_PER_SECOND,
        )
        if global_tokens < 1:
            self._global_bucket = (global_tokens, now)
            return False
        self._global_bucket = (global_tokens - 1, now)
        return True

    def handle_datagram(self, data: bytes, session) -> bytes | None:
        """Return the reply for one datagram, or None. Overridden by the capability."""
        raise NotImplementedError

    def process_datagram(self, data: bytes, addr, local_addr) -> bytes | None:
        if not self.valid_datagram(data) or not self._allow(addr[0]):
            return None
        key = (tuple(addr[:2]), tuple(local_addr[:2]))
        session = self._udp_sessions.get(key)
        if session is None:
            if self._limit_reached(addr):
                return None
            session = self.create_session(addr, local_addr)
            self._udp_sessions[key] = session
        old_handle = self._idle_handles.pop(key, None)
        if old_handle is not None:
            old_handle.cancel()
        self._idle_handles[key] = asyncio.get_running_loop().call_later(
            self.timeout, self._expire_udp_session, key
        )
        try:
            reply = self.handle_datagram(data, session)
        except Exception as exc:  # same policy as handle_session: never a traceback
            if isinstance(exc, _CLIENT_ERRORS):
                logger.debug(
                    "Client error in %s datagram [%s] %s", self.NAME, type(exc).__name__, exc
                )
            else:
                self._warn_error(exc, session)
            reply = None
        if reply and len(reply) > self.MAX_REPLY_RATIO * max(len(data), 1):
            logger.debug(
                "%s reply suppressed: %d bytes for a %d byte request",
                self.NAME,
                len(reply),
                len(data),
            )
            return None
        return reply

    def valid_datagram(self, data):
        return bool(data)

    def _expire_udp_session(self, key):
        self._idle_handles.pop(key, None)
        session = self._udp_sessions.pop(key, None)
        if session is not None:
            self.close_session(session)

    def close_datagram_sessions(self):
        for handle in self._idle_handles.values():
            handle.cancel()
        self._idle_handles.clear()
        for key in list(self._udp_sessions):
            self._expire_udp_session(key)


class _DatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, capability):
        self.capability = capability
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def connection_lost(self, exc):
        self.capability.close_datagram_sessions()

    def datagram_received(self, data, addr):
        local = self.transport.get_extra_info("sockname") or ("0.0.0.0", self.capability.port)
        if ipaddress.ip_address(local[0]).is_unspecified:
            # A connected temporary UDP socket asks the kernel which local address routes
            # to this peer; it sends no traffic and avoids logging 0.0.0.0 / ::.
            family = socket.AF_INET6 if ":" in addr[0] else socket.AF_INET
            try:
                with socket.socket(family, socket.SOCK_DGRAM) as route:
                    route.connect(addr)
                    local = (route.getsockname()[0], local[1])
            except OSError:
                return
        reply = self.capability.process_datagram(data, addr, local)
        if reply:
            self.transport.sendto(reply, addr)

    def error_received(self, exc):
        logger.debug(
            "%s datagram endpoint error [%s] %s", self.capability.NAME, type(exc).__name__, exc
        )

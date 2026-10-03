import json
import logging
import socket

from heralding.reporting.hub import Sink

logger = logging.getLogger(__name__)


def _bounded_client(client_type, host, port, ident, secret):
    # hpfeeds3's constructor calls tryconnect(), whose retry loop ignores
    # reconnect=False. Keep its authentication/framing but bound socket I/O.
    class BoundedClient(client_type):
        def tryconnect(self):
            with self.connecting_lock:
                if self.connected:
                    return
                self.close_old()
                try:
                    self.s = socket.create_connection((self.host, self.port), self.timeout)
                    self.unpacker.reset()
                    self.do_auth()
                    self.connected = True
                except Exception:
                    self.close_old()
                    self.s = None
                    raise

    return BoundedClient(host, port, ident, secret, timeout=3, reconnect=False)


class HpfeedsSink(Sink):
    name = "hpfeeds"

    def __init__(self, session_channel, auth_channel, host, port, ident, secret):
        self.session_channel = session_channel
        self.auth_channel = auth_channel
        self.host = host
        self.port = port
        self.ident = ident
        self.secret = secret
        self._conn = None
        self._client_type = None

    def open(self) -> None:
        try:
            from hpfeeds.client import Client
        except ImportError as exc:
            raise RuntimeError("hpfeeds logging requires 'uv sync --extra hpfeeds'") from exc
        self._client_type = Client
        self._connect()

    def _connect(self) -> None:
        self._conn = _bounded_client(
            self._client_type, self.host, self.port, self.ident, self.secret
        )
        logger.info("HpFeeds logger connected to %s:%s.", self.host, self.port)

    def _publish(self, channel, data) -> None:
        payload = json.dumps(data).encode()
        if self._conn is None:
            self._connect()
        try:
            self._conn.publish(channel, payload)
        except Exception:
            # one reconnect attempt; a second failure is caught by the worker
            self.close()
            self._connect()
            self._conn.publish(channel, payload)

    def handle_auth(self, data: dict) -> None:
        self._publish(self.auth_channel, data)

    def handle_session(self, data: dict) -> None:
        self._publish(self.session_channel, data)

    def close(self) -> None:
        connection, self._conn = self._conn, None
        if connection is not None:
            try:
                connection.close()
            except Exception as exc:
                logger.debug("HpFeeds connection close failed: %s", exc)

import json
import logging

from heralding.reporting.hub import Sink

logger = logging.getLogger(__name__)


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
        self._hpfeeds = None

    def open(self) -> None:
        try:
            import hpfeeds
        except ImportError as exc:
            raise RuntimeError("hpfeeds logging requires 'uv sync --extra hpfeeds'") from exc
        self._hpfeeds = hpfeeds
        self._connect()

    def _connect(self) -> None:
        self._conn = self._hpfeeds.new(self.host, self.port, self.ident, self.secret, True)
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

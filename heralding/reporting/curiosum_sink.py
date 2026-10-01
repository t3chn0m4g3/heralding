import json
import logging
import time

from heralding.reporting.hub import Sink

logger = logging.getLogger(__name__)


class CuriosumSink(Sink):
    name = "curiosum"

    def __init__(self, port: int):
        self.port = port
        self.listen_ports: list[int] = []
        self._last_ports_sent = 0.0
        self._socket = None
        self._ctx = None
        self._zmq = None

    def open(self) -> None:
        try:
            import zmq
        except ImportError as exc:
            raise RuntimeError(
                "curiosum integration requires 'uv sync --extra curiosum'"
            ) from exc
        self._zmq = zmq
        self._ctx = zmq.Context()
        self._socket = self._ctx.socket(zmq.PUSH)
        self._socket.bind(f"tcp://127.0.0.1:{self.port}")
        logger.info("Curiosum logger started on tcp://127.0.0.1:%s", self.port)

    def close(self) -> None:
        if self._socket is not None:
            self._socket.close(0)
            self._ctx.term()

    def _send(self, topic, data) -> None:
        self._socket.send_string(f"{topic} {json.dumps(data)}", self._zmq.NOBLOCK)

    def handle_session(self, data: dict) -> None:
        self._send(
            "session_ended",
            {
                "SessionID": str(data["session_id"]),
                "DstPort": data["destination_port"],
                "SrcIP": data["source_ip"],
                "SrcPort": data["source_port"],
                "SessionEnded": data["session_ended"],
            },
        )

    def handle_listen_ports(self, ports) -> None:
        self.listen_ports = ports

    def tick(self) -> None:
        if time.monotonic() - self._last_ports_sent > 5:
            self._send("listen_ports", self.listen_ports)
            self._last_ports_sent = time.monotonic()

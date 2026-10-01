"""Reporting pipeline: sessions emit events, each sink consumes them on its own thread.

The event loop only ever calls ``put_nowait`` on bounded queues, so a slow or
broken sink can never stall the honeypot. Drops are counted and warned about
with rate limiting; exceptions inside a sink are logged and the sink keeps
running.
"""

import logging
import queue
import threading
import time

logger = logging.getLogger(__name__)

_QUEUE_POLL = 0.5
_WARN_INTERVAL = 60.0


class Sink:
    name = "sink"

    def open(self) -> None: ...

    def close(self) -> None: ...

    def handle_auth(self, data: dict) -> None: ...

    def handle_session(self, data: dict) -> None: ...

    def handle_listen_ports(self, ports: list[int]) -> None: ...

    def tick(self) -> None: ...


class _SinkWorker(threading.Thread):
    def __init__(self, sink: Sink, queue_size: int):
        super().__init__(name=f"sink-{sink.name}", daemon=True)
        self.sink = sink
        self.queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self.dropped = 0
        self.errors = 0
        self._last_warn = 0.0
        self._stopping = threading.Event()

    def put(self, item) -> None:
        try:
            self.queue.put_nowait(item)
        except queue.Full:
            self.dropped += 1
            self._warn("dropping events, queue full (%d dropped so far)", self.dropped)

    def _warn(self, msg, *args) -> None:
        now = time.monotonic()
        if now - self._last_warn >= _WARN_INTERVAL:
            self._last_warn = now
            logger.warning("Sink %s: " + msg, self.sink.name, *args)  # noqa: G003

    def run(self) -> None:
        try:
            while True:
                try:
                    kind, payload = self.queue.get(timeout=_QUEUE_POLL)
                except queue.Empty:
                    if self._stopping.is_set():
                        break
                    self._safe(self.sink.tick)
                    continue
                if kind == "auth":
                    self._safe(self.sink.handle_auth, payload)
                elif kind == "session":
                    self._safe(self.sink.handle_session, payload)
                elif kind == "listen_ports":
                    self._safe(self.sink.handle_listen_ports, payload)
        finally:
            self._safe(self.sink.close)

    def _safe(self, fn, *args) -> None:
        try:
            fn(*args)
        except Exception as exc:
            self.errors += 1
            self._warn("error in %s [%s] %s", fn.__name__, type(exc).__name__, exc)
            logger.debug("sink error", exc_info=True)

    def stop(self) -> None:
        self._stopping.set()


class ReportingHub:
    def __init__(self, queue_size: int = 10000):
        self._queue_size = queue_size
        self._workers: list[_SinkWorker] = []
        self._started = False

    def add_sink(self, sink: Sink) -> None:
        self._workers.append(_SinkWorker(sink, self._queue_size))

    def start(self) -> None:
        """Open every sink on the calling thread (so a broken log path fails startup), then
        start the worker threads."""
        for w in self._workers:
            w.sink.open()
        for w in self._workers:
            w.start()
        self._started = True

    def stop(self, timeout: float = 5.0) -> None:
        for w in self._workers:
            w.stop()
        deadline = time.monotonic() + timeout
        for w in self._workers:
            if w.is_alive():
                w.join(max(0.0, deadline - time.monotonic()))
        self._started = False

    def _emit(self, kind: str, payload) -> None:
        for w in self._workers:
            w.put((kind, payload))

    def emit_auth(self, data: dict) -> None:
        self._emit("auth", data)

    def emit_session(self, data: dict) -> None:
        self._emit("session", data)

    def emit_listen_ports(self, ports: list[int]) -> None:
        self._emit("listen_ports", list(ports))

    @property
    def dropped(self) -> int:
        return sum(w.dropped for w in self._workers)


_NULL_HUB = ReportingHub()
_current: ReportingHub = _NULL_HUB


def get_hub() -> ReportingHub:
    return _current


def set_hub(hub: ReportingHub | None) -> None:
    global _current
    _current = hub if hub is not None else _NULL_HUB


def build_hub(config: dict) -> ReportingHub:
    from heralding.reporting.file_sink import FileSink

    hub = ReportingHub()
    logging_cfg = config.get("activity_logging", {}) or {}
    file_cfg = logging_cfg.get("file", {}) or {}
    if file_cfg.get("enabled"):
        hub.add_sink(
            FileSink(
                file_cfg.get("session_csv_log_file", ""),
                file_cfg.get("session_json_log_file", ""),
                file_cfg.get("authentication_log_file", ""),
            )
        )
    syslog_cfg = logging_cfg.get("syslog", {}) or {}
    if syslog_cfg.get("enabled"):
        from heralding.reporting.syslog_sink import SyslogSink

        hub.add_sink(SyslogSink(level_name=syslog_cfg.get("level", "LOG_ALERT")))
    hp = logging_cfg.get("hpfeeds", {}) or {}
    if hp.get("enabled"):
        from heralding.reporting.hpfeeds_sink import HpfeedsSink

        hub.add_sink(
            HpfeedsSink(
                hp["session_channel"],
                hp["auth_channel"],
                hp["host"],
                int(hp["port"]),
                hp["ident"],
                hp["secret"],
            )
        )
    cur = logging_cfg.get("curiosum", {}) or {}
    if cur.get("enabled"):
        from heralding.reporting.curiosum_sink import CuriosumSink

        hub.add_sink(CuriosumSink(int(cur["port"])))
    return hub

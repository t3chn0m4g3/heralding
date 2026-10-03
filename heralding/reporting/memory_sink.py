import threading

from heralding.reporting.hub import Sink


class MemorySink(Sink):
    """In-memory sink for tests."""

    name = "memory"

    def __init__(self):
        self.auth: list[dict] = []
        self.sessions: list[dict] = []
        self._cond = threading.Condition()

    def handle_auth(self, data):
        with self._cond:
            self.auth.append(data)
            self._cond.notify_all()

    def handle_session(self, data):
        with self._cond:
            self.sessions.append(data)
            self._cond.notify_all()

    def wait_for_auth(self, count: int, timeout: float = 5.0) -> list[dict]:
        with self._cond:
            if not self._cond.wait_for(lambda: len(self.auth) >= count, timeout):
                raise AssertionError(f"expected {count} auth events, got {len(self.auth)}")
            return list(self.auth)

    def wait_for_session_end(self, count: int = 1, timeout: float = 5.0) -> list[dict]:
        with self._cond:
            ok = self._cond.wait_for(
                lambda: sum(1 for s in self.sessions if s["session_ended"]) >= count, timeout
            )
            if not ok:
                raise AssertionError("expected ended sessions")
            return [s for s in self.sessions if s["session_ended"]]

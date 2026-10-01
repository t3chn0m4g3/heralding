import csv
import json
import threading
import time

from heralding.reporting.file_sink import AUTH_FIELDS, FileSink
from heralding.reporting.hub import ReportingHub, Sink
from heralding.reporting.memory_sink import MemorySink


def _auth(**over):
    base = {
        "timestamp": "2026-10-01 12:00:00.000000",
        "auth_id": "a",
        "session_id": "s",
        "source_ip": "1.2.3.4",
        "source_port": 1,
        "destination_ip": "5.6.7.8",
        "destination_port": 21,
        "protocol": "ftp",
        "username": "u",
        "password": "p",
        "password_hash": None,
    }
    base.update(over)
    return base


def test_memory_sink_receives_auth():
    hub = ReportingHub()
    mem = MemorySink()
    hub.add_sink(mem)
    hub.start()
    try:
        hub.emit_auth(_auth())
        assert mem.wait_for_auth(1)[0]["username"] == "u"
    finally:
        hub.stop()


def test_full_queue_drops_and_counts():
    class Blocking(Sink):
        name = "blocking"

        def __init__(self):
            self.release = threading.Event()

        def handle_auth(self, data):
            self.release.wait()

    hub = ReportingHub(queue_size=2)
    blocking = Blocking()
    hub.add_sink(blocking)
    hub.start()
    try:
        start = time.monotonic()
        for _ in range(10):
            hub.emit_auth(_auth())
        assert time.monotonic() - start < 0.5  # never blocks the caller
        assert hub.dropped >= 7
    finally:
        blocking.release.set()
        hub.stop()


def test_sink_exception_does_not_kill_worker():
    class Flaky(MemorySink):
        def handle_auth(self, data):
            if data["username"] == "boom":
                raise ValueError("boom")
            super().handle_auth(data)

    hub = ReportingHub()
    flaky = Flaky()
    hub.add_sink(flaky)
    hub.start()
    try:
        hub.emit_auth(_auth(username="boom"))
        hub.emit_auth(_auth(username="ok"))
        assert flaky.wait_for_auth(1)[0]["username"] == "ok"
    finally:
        hub.stop()


def test_stop_drains_queue(tmp_path):
    auth = tmp_path / "auth.csv"
    hub = ReportingHub()
    hub.add_sink(FileSink("", "", str(auth)))
    hub.start()
    for i in range(50):
        hub.emit_auth(_auth(auth_id=str(i)))
    hub.stop()
    rows = list(csv.DictReader(auth.open(encoding="utf-8")))
    assert len(rows) == 50
    assert list(rows[0].keys()) == list(AUTH_FIELDS)


def test_file_sink_header_only_when_empty(tmp_path):
    auth = tmp_path / "auth.csv"
    for _ in range(2):
        sink = FileSink("", "", str(auth))
        sink.open()
        sink.handle_auth(_auth())
        sink.close()
    lines = auth.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("timestamp,auth_id,session_id")
    assert len(lines) == 3


def test_file_sink_non_utf8_and_none_values(tmp_path):
    auth = tmp_path / "auth.csv"
    sink = FileSink("", "", str(auth))
    sink.open()
    sink.handle_auth(_auth(username="пайт\udc80он", password=None))
    sink.close()
    rows = list(csv.DictReader(auth.open(encoding="utf-8", errors="replace")))
    assert rows[0]["username"].startswith("пайт")


def test_session_json_is_jsonl_with_contract_keys(tmp_path):
    sess = tmp_path / "log_session.json"
    sink = FileSink("", str(sess), "")
    sink.open()
    sink.handle_session(
        {
            "timestamp": "2026-10-01 12:00:00.000000",
            "duration": 1,
            "session_id": "s",
            "source_ip": "1.2.3.4",
            "source_port": 1,
            "destination_ip": "5.6.7.8",
            "destination_port": 21,
            "protocol": "ftp",
            "num_auth_attempts": 1,
            "auth_attempts": [
                {
                    "timestamp": "x",
                    "username": "u",
                    "password": "p",
                    "auth_id": "a",
                    "password_hash": None,
                    "method": "plaintext",
                }
            ],
            "session_ended": True,
            "auxiliary_data": {},
        }
    )
    sink.close()
    event = json.loads(sess.read_text().splitlines()[0])
    assert event["session_ended"] is True
    assert event["auth_attempts"][0]["username"] == "u"

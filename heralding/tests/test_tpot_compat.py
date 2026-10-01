"""Guards the log format that T-Pot (logstash, ewsposter, smoke test) consumes."""

import csv
import io
import json
import re
from pathlib import Path

import yaml

from heralding.misc.session import Session
from heralding.reporting.file_sink import AUTH_FIELDS, FileSink
from heralding.reporting.hub import ReportingHub, set_hub

TS_RE = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{6}$")
FIXTURES = Path(__file__).parent / "fixtures"


def _run_session(tmp_path):
    hub = ReportingHub()
    hub.add_sink(
        FileSink(
            str(tmp_path / "session.csv"),
            str(tmp_path / "log_session.json"),
            str(tmp_path / "auth.csv"),
        )
    )
    hub.start()
    set_hub(hub)
    try:
        s = Session("10.0.0.1", 40000, "ftp", {}, 21, "10.0.0.2")
        s.add_auth_attempt("plaintext", username="user,with,commas", password='pa"ss')
        s.end_session()
    finally:
        hub.stop()
        set_hub(None)


def test_auth_csv_positions_and_header(tmp_path):
    _run_session(tmp_path)
    lines = (tmp_path / "auth.csv").read_text(encoding="utf-8").splitlines()
    assert lines[0].split(",")[:11] == list(AUTH_FIELDS)
    assert "timestamp" in lines[0]
    row = next(csv.DictReader(io.StringIO("\n".join(lines))))
    assert TS_RE.match(row["timestamp"])
    assert row["protocol"] == "ftp"
    assert row["username"] == "user,with,commas"
    assert row["password"] == 'pa"ss'
    # ewsposter: line[0:19] is the second-resolution timestamp
    assert re.match(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$", lines[1][0:19])


def test_session_json_contract(tmp_path):
    _run_session(tmp_path)
    event = json.loads((tmp_path / "log_session.json").read_text().splitlines()[0])
    assert event["protocol"] == "ftp"
    assert event["session_ended"] is True
    assert event["num_auth_attempts"] == 1
    assert event["auth_attempts"][0]["username"] == "user,with,commas"
    assert event["auth_attempts"][0]["password"] == 'pa"ss'


def test_tpot_config_loads():
    config = yaml.safe_load((FIXTURES / "tpot_heralding.yml").read_text())
    assert (
        config["activity_logging"]["file"]["authentication_log_file"]
        == "/var/log/heralding/auth.csv"
    )
    assert config["public_ip_as_destination_ip"] is True
    assert set(config["capabilities"]) == {
        "ftp",
        "telnet",
        "pop3",
        "pop3s",
        "postgresql",
        "imap",
        "imaps",
        "ssh",
        "http",
        "https",
        "smtp",
        "smtps",
        "vnc",
        "socks5",
        "mysql",
        "rdp",
    }


def test_session_start_event_does_not_alias_live_lists(tmp_path):
    from heralding.reporting.memory_sink import MemorySink

    hub = ReportingHub()
    mem = MemorySink()
    hub.add_sink(mem)
    hub.start()
    set_hub(hub)
    try:
        s = Session("10.0.0.1", 40000, "ftp", {}, 21, "10.0.0.2")
        s.add_auth_attempt("plaintext", username="a", password="b")
        s.end_session()
    finally:
        hub.stop()
        set_hub(None)
    start_event = mem.sessions[0]
    assert start_event["session_ended"] is False
    assert start_event["auth_attempts"] == []  # a copy taken at emit time, not the live list

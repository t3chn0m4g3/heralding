"""Stable public log format and generic configuration/startup contracts."""

import asyncio
import csv
import io
import json
import re

import pytest

from heralding.misc.session import Session
from heralding.reporting.file_sink import AUTH_FIELDS, FileSink
from heralding.reporting.hub import ReportingHub, set_hub
from heralding.tests.conftest import load_default_config

TS_RE = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{6}$")


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
    # A CSV row starts with the timestamp, independently of downstream consumers.
    assert re.match(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$", lines[1][0:19])


def test_session_json_contract(tmp_path):
    _run_session(tmp_path)
    event = json.loads((tmp_path / "log_session.json").read_text().splitlines()[0])
    assert event["protocol"] == "ftp"
    assert event["session_ended"] is True
    assert event["num_auth_attempts"] == 1
    assert event["auth_attempts"][0]["username"] == "user,with,commas"
    assert event["auth_attempts"][0]["password"] == 'pa"ss'


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


@pytest.mark.parametrize("legacy", [True, False])
async def test_honeypot_starts_with_explicit_or_legacy_config(tmp_path, monkeypatch, legacy):
    """Older configs may omit persona and optional protocol settings."""
    from heralding.capabilities import smtp
    from heralding.capabilities.handlerbase import HandlerBase
    from heralding.honeypot import Honeypot
    from heralding.reporting.memory_sink import MemorySink

    monkeypatch.chdir(tmp_path)
    config = load_default_config()
    if legacy:
        config.pop("persona", None)
        config["capabilities"]["mysql"].pop("protocol_specific_data", None)
    config["public_ip_as_destination_ip"] = False
    config["bind_host"] = "127.0.0.1"
    for cap in config["capabilities"].values():
        cap["port"] = 0
    hub = ReportingHub()
    hub.add_sink(MemorySink())
    hub.start()
    set_hub(hub)
    honeypot = Honeypot(config)
    try:
        await honeypot.start()
        assert len(honeypot._servers) == len(config["capabilities"])
        assert HandlerBase.persona is not None
        # CRAM-MD5 challenges use the persona FQDN, never the container's real host name
        assert smtp.SMTPHandler.fqdn == HandlerBase.persona.fqdn
        assert (tmp_path / "persona.state").exists()
        assert (tmp_path / "https.pem.persona").read_text() == HandlerBase.persona.fqdn
        # MSSQL's login TLS uses a certificate named like SQL Server's self-signed one
        from cryptography import x509

        mssql_cert = x509.load_pem_x509_certificate((tmp_path / "mssql.pem").read_bytes())
        assert mssql_cert.subject.rfc4514_string() == "CN=SSL_Self_Signed_Fallback"
        mssql_cap = next(c for c in honeypot._capabilities if c.NAME == "mssql")
        assert mssql_cap.starttls_context is not None
        # a second start in the same directory keeps the identity and the certificates
        pem_before = (tmp_path / "https.pem").read_bytes()
        identity = (HandlerBase.persona.name, HandlerBase.persona.hostname)
        await honeypot.stop()
        honeypot = Honeypot(config)
        await honeypot.start()
        assert (HandlerBase.persona.name, HandlerBase.persona.hostname) == identity
        assert (tmp_path / "https.pem").read_bytes() == pem_before
    finally:
        await honeypot.stop()
        HandlerBase.set_persona(None)
        smtp.set_fqdn("", source="persona")
        hub.stop()
        set_hub(None)


async def test_honeypot_starts_with_default_config(tmp_path, monkeypatch):
    """All capabilities of the shipped heralding.yml, including the UDP endpoint, start and stop."""
    from heralding.capabilities.handlerbase import HandlerBase
    from heralding.honeypot import Honeypot
    from heralding.reporting.memory_sink import MemorySink

    monkeypatch.chdir(tmp_path)
    config = load_default_config()
    config["bind_host"] = "127.0.0.1"
    for cap in config["capabilities"].values():
        cap["port"] = 0
    hub = ReportingHub()
    hub.add_sink(MemorySink())
    hub.start()
    set_hub(hub)
    honeypot = Honeypot(config)
    try:
        await honeypot.start()
        enabled = [c for c in config["capabilities"].values() if c.get("enabled")]
        assert len(honeypot._servers) == len(enabled)
        assert len(honeypot._datagram_transports) == 1  # sip over UDP
        transports = list(honeypot._datagram_transports)
    finally:
        await honeypot.stop()
        HandlerBase.set_persona(None)
        hub.stop()
        set_hub(None)
    assert all(t.is_closing() for t in transports)


@pytest.mark.parametrize("name", ["ftp", "submission"])
async def test_unloadable_starttls_cert_keeps_plain_auth_working(
    name, tmp_path, monkeypatch, caplog
):
    import ftplib
    import logging
    import smtplib

    from heralding.capabilities.handlerbase import HandlerBase
    from heralding.honeypot import Honeypot
    from heralding.reporting.memory_sink import MemorySink

    monkeypatch.chdir(tmp_path)
    (tmp_path / f"{name}.pem").write_text("not a certificate")
    caplog.set_level(logging.WARNING)
    config = load_default_config()
    config["public_ip_as_destination_ip"] = False
    config["bind_host"] = "127.0.0.1"
    cap_config = dict(config["capabilities"]["ftp"], port=0)
    if name == "submission":
        cap_config = {"enabled": True, "port": 0, "timeout": 5}
    config["capabilities"] = {name: cap_config}
    hub = ReportingHub()
    mem = MemorySink()
    hub.add_sink(mem)
    hub.start()
    set_hub(hub)
    honeypot = Honeypot(config)
    try:
        await honeypot.start()
        port = honeypot._servers[0].sockets[0].getsockname()[1]

        def login():
            if name == "ftp":
                client = ftplib.FTP()
                client.connect("127.0.0.1", port, timeout=5)
                try:
                    assert "AUTH TLS" not in client.sendcmd("FEAT")
                    with pytest.raises(ftplib.error_perm):
                        client.login("u", "p")
                finally:
                    client.close()
            else:
                with smtplib.SMTP(
                    "127.0.0.1", port, local_hostname="localhost", timeout=5
                ) as client:
                    client.ehlo()
                    assert not client.has_extn("starttls")
                    with pytest.raises(smtplib.SMTPAuthenticationError):
                        client.auth("PLAIN", lambda challenge=None: "\0u\0p")

        await asyncio.to_thread(login)
        assert (await asyncio.to_thread(mem.wait_for_auth, 1))[0]["username"] == "u"
    finally:
        await honeypot.stop()
        HandlerBase.set_persona(None)
        hub.stop()
        set_hub(None)
    assert any("AUTH TLS disabled" in r.getMessage() for r in caplog.records)

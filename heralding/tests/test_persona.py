import random

import pytest

from heralding.misc import persona

REQUIRED = {"ubuntu-24.04", "debian-12", "windows-server-2019", "windows-server-2022", "rhel-9"}
CAPS = ("ftp", "pop3", "imap", "smtp", "http", "ssh", "mysql", "telnet")


def test_all_personas_have_required_keys():
    data = persona.load_personas()
    assert REQUIRED <= set(data)
    for name, p in data.items():
        for cap in CAPS:
            assert cap in p["capabilities"], f"{name} lacks {cap}"
        caps = p["capabilities"]
        assert caps["ftp"]["banner"] and caps["ftp"]["syst_type"]
        assert caps["ssh"]["banner"].startswith("SSH-2.0-")
        assert caps["pop3"]["banner"].startswith("+OK")
        assert caps["imap"]["banner"].startswith("* OK")
        assert caps["http"]["banner"]
        assert caps["mysql"]["version"]
        assert "hostname_pattern" in p and "domain" in p and "cert" in p


def test_select_random_is_deterministic_with_seed():
    cfg = {"persona": "random"}
    a = persona.select_persona(cfg, random.Random(1))
    b = persona.select_persona(cfg, random.Random(1))
    assert (a.name, a.hostname) == (b.name, b.hostname)


def test_select_by_name_and_unknown_raises():
    p = persona.select_persona({"persona": "debian-12"})
    assert p.name == "debian-12"
    with pytest.raises(ValueError):
        persona.select_persona({"persona": "amiga-os"})


def test_default_is_random_when_key_missing():
    assert persona.select_persona({}).name in persona.load_personas()


def test_hostname_pattern():
    rng = random.Random(7)
    h = persona.make_hostname("mail-{n2}.{domain}", rng, domain="example.net")
    assert h.startswith("mail-") and h.endswith(".example.net") and h[5:7].isdigit()


def test_values_are_formatted_with_hostname():
    p = persona.select_persona({"persona": "ubuntu-24.04"}, random.Random(2))
    banner = p.get("smtp", "banner")
    assert p.hostname in banner and p.domain in banner


def test_get_returns_none_for_unknown_key():
    p = persona.select_persona({"persona": "ubuntu-24.04"})
    assert p.get("ftp", "banner")
    assert p.get("ftp", "no_such_key") is None
    assert p.get("no_such_cap", "banner") is None
    assert p.get("telnet", "banner") is None  # empty mapping, no banner


# --- persona wiring into capabilities (Task 2) ---

import asyncio  # noqa: E402

import yaml  # noqa: E402

from heralding.capabilities import ftp, http, pop3, smtp, ssh  # noqa: E402
from heralding.capabilities.handlerbase import HandlerBase  # noqa: E402
from heralding.tests.conftest import make_options  # noqa: E402
from heralding.tests.test_tpot_compat import FIXTURES  # noqa: E402


@pytest.fixture
def windows_persona():
    p = persona.select_persona({"persona": "windows-server-2022"}, random.Random(3))
    HandlerBase.set_persona(p)
    yield p
    HandlerBase.set_persona(None)


async def test_persona_banner_used_when_config_empty(serve, sink, windows_persona):
    host, port = await serve(ftp.ftp(make_options(max_attempts=3, banner="", syst_type="")))
    reader, writer = await asyncio.open_connection(host, port)
    assert (await reader.readline()) == b"220 Microsoft FTP Service\r\n"
    writer.write(b"SYST\r\n")
    await writer.drain()
    assert (await reader.readline()) == b"215 Windows_NT\r\n"
    writer.close()


async def test_explicit_config_wins_for_tpot_fixture(serve, sink, windows_persona):
    cfg = yaml.safe_load((FIXTURES / "tpot_heralding.yml").read_text())
    host, port = await serve(pop3.Pop3(cfg["capabilities"]["pop3"]))
    reader, writer = await asyncio.open_connection(host, port)
    assert (await reader.readline()) == b"+OK POP3 server ready\n"
    writer.close()
    cap = ssh.SSH(cfg["capabilities"]["ssh"])
    assert cap.persona_value("banner") == "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8"


async def test_http_error_page_matches_persona(serve, sink, windows_persona):
    host, port = await serve(http.Http(make_options(banner="")))
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(b"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic %%%\r\n\r\n")
    await writer.drain()
    raw = await asyncio.wait_for(reader.read(), 5)
    assert b" 400 " in raw.split(b"\r\n")[0]
    assert b"Server: Microsoft-IIS/10.0" in raw
    assert b"Error response" not in raw and b"Python" not in raw
    writer.close()


async def test_head_has_no_body(serve, sink):
    host, port = await serve(http.Http(make_options(banner="x")))
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
    await writer.drain()
    raw = await asyncio.wait_for(reader.read(), 5)
    head, _, body = raw.partition(b"\r\n\r\n")
    assert b" 401 " in head and body == b""
    writer.close()


def test_smtp_banner_contains_persona_hostname(windows_persona):
    cap = smtp.smtp(make_options(banner="", fqdn=""))
    assert windows_persona.hostname in cap.persona_value("banner")


def test_persona_value_default_without_persona():
    HandlerBase.set_persona(None)
    cap = pop3.Pop3(make_options(max_attempts=3, banner=""))
    assert cap.persona_value("banner", "+OK POP3 server ready") == "+OK POP3 server ready"


# --- stable identity across restarts (review finding B-I1) ---


def test_random_persona_is_persisted_and_reused(tmp_path):
    state = tmp_path / "persona.state"
    first = persona.select_persona({"persona": "random"}, random.Random(1), state_path=str(state))
    assert state.exists()
    second = persona.select_persona({"persona": "random"}, random.Random(99), state_path=str(state))
    assert (second.name, second.hostname) == (first.name, first.hostname)


def test_named_persona_keeps_hostname_but_switches_on_config_change(tmp_path):
    state = tmp_path / "persona.state"
    a = persona.select_persona({"persona": "debian-12"}, random.Random(1), state_path=str(state))
    b = persona.select_persona({"persona": "debian-12"}, random.Random(2), state_path=str(state))
    assert (a.name, a.hostname) == (b.name, b.hostname)
    c = persona.select_persona({"persona": "rhel-9"}, random.Random(3), state_path=str(state))
    assert c.name == "rhel-9" and c.hostname != a.hostname or c.name == "rhel-9"
    assert state.read_text().count("rhel-9") == 1


def test_corrupt_state_file_is_ignored(tmp_path):
    state = tmp_path / "persona.state"
    state.write_text("{not json")
    p = persona.select_persona({"persona": "random"}, random.Random(1), state_path=str(state))
    assert p.name in persona.load_personas()
    assert state.read_text().startswith("{")


async def test_http_error_page_style_follows_explicit_banner_and_escapes_percent(
    serve, sink, windows_persona
):
    host, port = await serve(http.Http(make_options(banner="Apache/2.4.62 (Debian) 100%")))
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(b"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic %%%\r\n\r\n")
    await writer.drain()
    raw = await asyncio.wait_for(reader.read(), 5)
    assert b" 400 " in raw.split(b"\r\n")[0]
    assert b"Server: Apache/2.4.62 (Debian) 100%" in raw
    assert b"HTTP Error" not in raw  # IIS wording must not appear under an Apache banner
    assert b"<center>Apache/2.4.62 (Debian) 100%</center>" in raw
    writer.close()

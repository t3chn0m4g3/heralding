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

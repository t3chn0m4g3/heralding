import heralding.capabilities  # noqa: F401  registers everything
from heralding.capabilities.handlerbase import HandlerBase

EXPECTED = {
    "ftp": None,
    "telnet": None,
    "pop3": None,
    "pop3s": "implicit",
    "imap": None,
    "imaps": "implicit",
    "ssh": None,
    "http": None,
    "https": "implicit",
    "smtp": None,
    "smtps": "implicit",
    "vnc": None,
    "socks5": None,
    "mysql": None,
    "postgresql": None,
    "rdp": None,
    "redis": None,
    "mqtt": None,
    "mqtts": "implicit",
    "http_proxy": None,
    "submission": "starttls",
    "ftps": "implicit",
    "ldap": None,
    "ldaps": "implicit",
}


def test_registry_names_and_tls():
    reg = HandlerBase.registry()
    assert set(reg) == set(EXPECTED)
    for name, tls in EXPECTED.items():
        assert reg[name].TLS == tls, name
        assert reg[name].TRANSPORT == "tcp"


def test_registry_is_recursive():
    class Base(HandlerBase):
        NAME = "_test_base"

    class Child(Base):
        NAME = "_test_child"

    try:
        reg = HandlerBase.registry()
        assert reg["_test_child"] is Child
        assert reg["_test_base"] is Base
    finally:
        # cleanup so other tests don't see the fakes
        HandlerBase._registry.pop("_test_base", None)
        HandlerBase._registry.pop("_test_child", None)

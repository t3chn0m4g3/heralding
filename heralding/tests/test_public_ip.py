import pytest

from heralding.misc import common


def test_public_ip_falls_back(monkeypatch):
    calls = []

    def fake_fetch(url, timeout):
        calls.append(url)
        if len(calls) < 2:
            raise OSError("down")
        return "203.0.113.5\n"

    monkeypatch.setattr(common, "_fetch_text", fake_fetch)
    assert common.get_public_ip() == "203.0.113.5"
    assert len(calls) == 2


def test_public_ip_rejects_garbage(monkeypatch):
    monkeypatch.setattr(common, "_fetch_text", lambda url, timeout: "<html>not an ip</html>")
    with pytest.raises(RuntimeError):
        common.get_public_ip()


def test_public_ip_all_fail(monkeypatch):
    def fail(url, timeout):
        raise OSError("x")

    monkeypatch.setattr(common, "_fetch_text", fail)
    with pytest.raises(RuntimeError):
        common.get_public_ip()

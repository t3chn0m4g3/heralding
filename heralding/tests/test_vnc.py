import asyncio
import contextlib

import pytest
from vncdotool import api

import heralding.honeypot
from heralding.capabilities.vnc import Vnc
from heralding.tests.conftest import make_options


@pytest.fixture(scope="module", autouse=True)
def _vnc_reactor():
    # vncdotool runs one Twisted reactor thread per process; it cannot be restarted
    yield
    api.shutdown()


def _login(host, port, password):
    """Standard client: vncdotool connects with a password; the honeypot refuses it."""
    client = api.connect(f"{host}::{port}", password=password, timeout=5)
    with contextlib.suppress(Exception):  # authentication failure is the expected outcome
        client.refreshScreen()
    with contextlib.suppress(Exception):
        client.disconnect()


async def test_password_attempt_is_logged(serve, sink):
    host, port = await serve(Vnc(make_options()))
    await asyncio.to_thread(_login, host, port, "letmein")
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["protocol"] == "vnc"
    assert attempt["password_hash"].startswith("$vnc$*")


async def test_wordlist_hit_is_logged_in_clear(serve, sink, monkeypatch):
    monkeypatch.setattr(heralding.honeypot.Honeypot, "wordlist", ["wrong", "secret"])
    host, port = await serve(Vnc(make_options()))
    await asyncio.to_thread(_login, host, port, "secret")
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["password"] == "secret"
    assert attempt["password_hash"].startswith("$vnc$*")


async def test_non_ascii_wordlist_entry_is_tolerated(serve, sink, monkeypatch):
    monkeypatch.setattr(heralding.honeypot.Honeypot, "wordlist", ["pässwörd", "ünïcode"])
    host, port = await serve(Vnc(make_options()))
    await asyncio.to_thread(_login, host, port, "other")
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["password"] is None


def test_crack_semaphore_is_per_instance():
    a, b = Vnc(make_options()), Vnc(make_options())
    assert a._semaphore() is not b._semaphore()


async def test_busy_cracker_is_skipped_and_the_hash_logged(serve, sink, monkeypatch):
    monkeypatch.setattr(heralding.honeypot.Honeypot, "wordlist", ["secret"])
    cap = Vnc(make_options())
    for _ in range(2):  # both crack slots taken
        await cap._semaphore().acquire()
    host, port = await serve(cap)
    await asyncio.to_thread(_login, host, port, "secret")
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["password"] is None and attempt["password_hash"].startswith("$vnc$*")


async def test_session_timeout_during_crack_still_logs_the_hash(serve, sink, monkeypatch):
    import threading

    release = threading.Event()
    monkeypatch.setattr(heralding.honeypot.Honeypot, "wordlist", ["secret"])
    monkeypatch.setattr(
        "heralding.capabilities.vnc.crack_hash", lambda *args: release.wait(10) and None
    )
    cap = Vnc(make_options())
    cap.timeout = 1
    host, port = await serve(cap)
    try:
        await asyncio.to_thread(_login, host, port, "secret")
        attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
        assert attempt["password_hash"].startswith("$vnc$*")
        assert cap._semaphore().locked() is False and cap._semaphore()._value == 1
    finally:
        release.set()

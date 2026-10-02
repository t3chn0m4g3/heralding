import asyncio
import socket

from pyVoIP.VoIP import VoIPPhone

from heralding.capabilities import sip
from heralding.tests.conftest import make_options


def _free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _udp_server(sink, **options):
    cap = sip.Sip(make_options(**options))
    transport, _ = await cap.create_datagram_endpoint("127.0.0.1", 0)
    return transport, transport.get_extra_info("sockname")[1]


def _register(host, port, username, password, sink):
    """Standard client: pyVoIP sends REGISTER, answers the Digest challenge with the password
    and keeps retrying in the background; we stop it once our side has logged the attempt."""
    phone = VoIPPhone(host, port, username, password, myIP="127.0.0.1", sipPort=_free_udp_port())
    phone.start()
    try:
        sink.wait_for_auth(1, timeout=10)
    finally:
        phone.stop()


async def test_register_with_standard_client_is_logged(sink):
    transport, port = await _udp_server(sink)
    try:
        await asyncio.to_thread(_register, "127.0.0.1", port, "1001", "s3cret", sink)
    finally:
        transport.close()
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["username"] == "1001" and attempt["protocol"] == "sip"
    assert attempt["password_hash"].startswith("$sip$*")
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert any("REGISTER" in s["auxiliary_data"].get("commands", [""])[0] for s in ended)


def test_udp_token_bucket_limits_bursts_and_refills(monkeypatch):
    now = 100.0
    monkeypatch.setattr("heralding.capabilities.handlerbase.time.monotonic", lambda: now)
    cap = sip.Sip(make_options())
    source = "192.0.2.1"
    assert all(cap._allow(source) for _ in range(cap.BUCKET_SIZE))
    assert not cap._allow(source)
    assert cap._allow("192.0.2.2")
    now += 1 / cap.REFILL_PER_SECOND
    assert cap._allow(source)
    assert not cap._allow(source)
    now += 100
    assert all(cap._allow(source) for _ in range(cap.BUCKET_SIZE))
    assert not cap._allow(source)

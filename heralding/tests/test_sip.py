import asyncio
import hashlib
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


async def test_register_with_standard_client_is_logged_and_hash_verifies(sink):
    transport, port = await _udp_server(sink)
    try:
        await asyncio.to_thread(_register, "127.0.0.1", port, "1001", "s3cret", sink)
    finally:
        transport.close()
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["username"] == "1001" and attempt["protocol"] == "sip"
    f = attempt["password_hash"].split("*")
    assert f[0] == "$sip$" and f[3] == "1001" and f[5] == "REGISTER"
    realm, nonce, uri, response = f[4], f[10], f"{f[6]}:{f[8]}", f[15]
    # the logged material must verify against the known password (RFC 2617, no qop)
    ha1 = hashlib.md5(f"1001:{realm}:s3cret".encode()).hexdigest()  # noqa: S324
    ha2 = hashlib.md5(f"REGISTER:{uri}".encode()).hexdigest()  # noqa: S324
    assert hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest() == response  # noqa: S324
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert any("REGISTER" in s["auxiliary_data"].get("commands", [""])[0] for s in ended)


async def test_tcp_transport_with_standard_client_payload(serve, sink):
    host, port = await serve(sip.Sip(make_options()))
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(
        f"OPTIONS sip:{host} SIP/2.0\r\nVia: SIP/2.0/TCP 192.0.2.1;branch=z9hG4bK1\r\n"
        f"From: <sip:probe@{host}>;tag=1\r\nTo: <sip:probe@{host}>\r\nCall-ID: 1\r\n"
        f"CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n".encode()
    )
    await writer.drain()
    response = await asyncio.wait_for(reader.read(4096), 5)
    assert response.startswith(b"SIP/2.0 200 OK") and b"User-Agent: " in response
    writer.close()


# --- robustness tests: no client can produce these inputs, so they stay raw on purpose ---


def _udp_send(host, port, payload, timeout=1.0):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(payload, (host, port))
        try:
            return s.recv(4096)
        except TimeoutError:
            return b""


async def test_udp_flood_from_one_source_is_rate_limited(sink):
    transport, port = await _udp_server(sink)
    try:
        probe = b"OPTIONS sip:h SIP/2.0\r\nVia: SIP/2.0/UDP a;branch=1\r\nCall-ID: 1\r\nCSeq: 1 OPTIONS\r\n\r\n"

        def flood():
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0.5)
                for _ in range(200):
                    s.sendto(probe, ("127.0.0.1", port))
                replies = 0
                while True:
                    try:
                        s.recv(4096)
                        replies += 1
                    except TimeoutError:
                        return replies

        assert 0 < await asyncio.to_thread(flood) <= sip.Sip.BUCKET_SIZE + 5
    finally:
        transport.close()

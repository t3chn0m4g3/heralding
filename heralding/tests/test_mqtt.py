import asyncio
import ssl
import threading

import paho.mqtt.client as paho
import pytest

from heralding.capabilities import mqtt, mqtts
from heralding.tests.conftest import make_options


def _connect(host, port, username, password, protocol, tls=False, timeout=10):
    """Connect with paho and return the CONNACK reason code (int)."""
    done = threading.Event()
    result = {}

    def on_connect(client, userdata, flags, reason_code, properties=None):
        result["rc"] = int(reason_code.value) if hasattr(reason_code, "value") else int(reason_code)
        done.set()

    client = paho.Client(paho.CallbackAPIVersion.VERSION2, client_id="probe-1", protocol=protocol)
    client.on_connect = on_connect
    if username is not None:
        client.username_pw_set(username, password)
    if tls:
        client.tls_set(cert_reqs=ssl.CERT_NONE)  # honeypot cert is self-signed
        client.tls_insecure_set(True)
    client.connect(host, port, keepalive=5)
    client.loop_start()
    try:
        assert done.wait(timeout), "no CONNACK"
    finally:
        client.loop_stop()
        client.disconnect()
    return result["rc"]


# paho's VERSION2 callbacks normalise v3 return codes to the v5 reason code values:
# 4 (bad user name or password) -> 134, 5 (not authorized) -> 135
BAD_CREDENTIALS = 134
NOT_AUTHORIZED = 135


@pytest.mark.parametrize("protocol", [paho.MQTTv311, paho.MQTTv5, paho.MQTTv31])
async def test_connect_with_credentials_is_refused_and_logged(serve, sink, protocol):
    host, port = await serve(mqtt.Mqtt(make_options()))
    rc = await asyncio.to_thread(_connect, host, port, "iot-user", "iot-pass", protocol)
    assert rc == BAD_CREDENTIALS
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("iot-user", "iot-pass")
    assert attempt["protocol"] == "mqtt"
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    aux = ended[0]["auxiliary_data"]
    assert aux["client_id"] == "probe-1"
    assert aux["mqtt_version"] in (3, 4, 5)


async def test_connect_without_credentials_is_not_authorized(serve, sink):
    host, port = await serve(mqtt.Mqtt(make_options()))
    rc = await asyncio.to_thread(_connect, host, port, None, None, paho.MQTTv311)
    assert rc == NOT_AUTHORIZED
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert ended[0]["num_auth_attempts"] == 0


async def test_mqtts_over_tls(serve, sink, server_ssl_context):
    host, port = await serve(mqtts.Mqtts(make_options()), server_ssl_context)
    rc = await asyncio.to_thread(_connect, host, port, "u", "p", paho.MQTTv311, True)
    assert rc == BAD_CREDENTIALS
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["protocol"] == "mqtts"


async def test_non_utf8_password_is_logged(serve, sink):
    host, port = await serve(mqtt.Mqtt(make_options()))
    # paho accepts a bytes password, so the client itself sends the raw Latin-1 byte
    rc = await asyncio.to_thread(_connect, host, port, "u", b"p\xe4", paho.MQTTv311)
    assert rc == BAD_CREDENTIALS
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["password"] == "p\\xe4"

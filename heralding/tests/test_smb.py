import asyncio
import uuid

import pytest
from smbprotocol.connection import Connection
from smbprotocol.exceptions import LogonFailure
from smbprotocol.session import Session

from heralding.capabilities.smb import Smb
from heralding.tests.conftest import make_options


@pytest.mark.parametrize("protocol", ["ntlm", "negotiate"])
@pytest.mark.parametrize("level", [0, 3])
async def test_standard_client_login_is_refused_and_material_logged(
    serve, sink, protocol, level, monkeypatch
):
    monkeypatch.setenv("LM_COMPAT_LEVEL", str(level))
    host, port = await serve(Smb(make_options()))

    def login():
        connection = Connection(uuid.uuid4(), host, port=port, require_signing=False)
        try:
            connection.connect(timeout=5)
            assert connection.dialect == 0x0302  # highest dialect without negotiate contexts
            session = Session(
                connection,
                username="CORP\\alice",
                password="secret",
                require_encryption=False,
                auth_protocol=protocol,
            )
            with pytest.raises(LogonFailure):
                session.connect()
        finally:
            connection.disconnect()

    await asyncio.to_thread(login)
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert attempt["protocol"] == "smb"
    assert attempt["username"] == "CORP\\alice"
    assert attempt["password"] is None
    assert attempt["password_hash"].startswith("alice::CORP:")
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    assert ended[0]["auxiliary_data"]["domain"] == "CORP"
    assert ended[0]["auth_attempts"][0]["method"] == ("ntlmv2" if level >= 3 else "ntlmv1")

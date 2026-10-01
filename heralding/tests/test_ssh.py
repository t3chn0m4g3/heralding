import asyncio
import gc

import asyncssh
import pytest

from heralding.capabilities import ssh
from heralding.tests.conftest import make_options


@pytest.fixture
async def ssh_server(sink, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # ssh.key is created in the working directory
    cap = ssh.SSH(make_options(banner="SSH-2.0-OpenSSH_9.6"))
    server = await cap.create_server("127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()[:2]
    yield host, port
    server.close()
    await server.wait_closed()


async def test_basic_login(ssh_server, sink):
    host, port = ssh_server
    with pytest.raises(asyncssh.PermissionDenied):
        async with asyncssh.connect(
            host, port, username="johnny", password="secretpw", known_hosts=None
        ):
            pass
    attempts = await asyncio.to_thread(sink.wait_for_auth, 1)
    assert (attempts[0]["username"], attempts[0]["password"]) == ("johnny", "secretpw")
    assert attempts[0]["protocol"] == "ssh"


async def test_banner_comes_from_config(ssh_server):
    host, port = ssh_server
    reader, writer = await asyncio.open_connection(host, port)
    assert (await reader.readline()).startswith(b"SSH-2.0-OpenSSH_9.6")
    writer.close()


async def test_keyboard_interactive_is_logged(ssh_server, sink):
    host, port = ssh_server
    with pytest.raises(asyncssh.PermissionDenied):
        async with asyncssh.connect(
            host,
            port,
            username="kbd",
            password="pw",
            known_hosts=None,
            preferred_auth=["keyboard-interactive"],
        ):
            pass
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("kbd", "pw")


async def test_connections_are_released(ssh_server, sink):
    host, port = ssh_server
    for _ in range(3):
        with pytest.raises(asyncssh.PermissionDenied):
            async with asyncssh.connect(host, port, username="u", password="p", known_hosts=None):
                pass
    await asyncio.sleep(0.3)
    gc.collect()
    assert len(ssh.SSH.connections) == 0


async def test_key_file_mode(tmp_path):
    path = tmp_path / "ssh.key"
    ssh.SSH.generate_ssh_key(str(path))
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert path.read_bytes().startswith(b"-----BEGIN")


async def test_public_key_attempt_is_logged_as_aux_not_auth(ssh_server, sink):
    host, port = ssh_server
    key = asyncssh.generate_private_key("ssh-ed25519")
    with pytest.raises(asyncssh.PermissionDenied):
        async with asyncssh.connect(
            host,
            port,
            username="deploy",
            client_keys=[key],
            known_hosts=None,
            preferred_auth=["publickey"],
        ):
            pass
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    attempts = ended[0]["auxiliary_data"]["publickey_attempts"]
    assert attempts[0]["username"] == "deploy"
    assert attempts[0]["key_type"] == "ssh-ed25519"
    assert attempts[0]["fingerprint_sha256"] == key.get_fingerprint("sha256")
    assert sink.auth == []  # no auth.csv line for key attempts

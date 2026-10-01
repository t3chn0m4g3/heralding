import asyncio

import asyncssh
import pytest

from heralding.capabilities import ssh
from heralding.tests.conftest import make_options


@pytest.fixture
async def ssh_server(sink, tmp_path):
    key = tmp_path / "ssh.key"
    ssh.SSH.generate_ssh_key(str(key))
    options = make_options(banner="SSH-2.0-OpenSSH_9.6")
    server = await asyncssh.create_server(
        lambda: ssh.SSH(options),
        "127.0.0.1",
        0,
        server_host_keys=[str(key)],
        login_timeout=5,
    )
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

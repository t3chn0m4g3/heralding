import asyncio
import ssl
from collections.abc import Awaitable, Callable

import pytest

from heralding.reporting.hub import ReportingHub, set_hub
from heralding.reporting.memory_sink import MemorySink


def make_options(port: int = 0, timeout: int = 30, **protocol_specific_data) -> dict:
    return {
        "enabled": True,
        "port": port,
        "timeout": timeout,
        "protocol_specific_data": protocol_specific_data,
    }


@pytest.fixture
def sink():
    hub = ReportingHub()
    mem = MemorySink()
    hub.add_sink(mem)
    hub.start()
    set_hub(hub)
    try:
        yield mem
    finally:
        hub.stop()
        set_hub(None)


@pytest.fixture
async def serve(sink) -> Callable[..., Awaitable[tuple[str, int]]]:
    servers: list[asyncio.AbstractServer] = []

    async def _serve(capability, ssl_context: ssl.SSLContext | None = None) -> tuple[str, int]:
        server = await asyncio.start_server(
            capability.handle_session, "127.0.0.1", 0, ssl=ssl_context
        )
        servers.append(server)
        host, port = server.sockets[0].getsockname()[:2]
        return host, port

    yield _serve
    for server in servers:
        server.close()
        server.close_clients()
        await asyncio.wait_for(server.wait_closed(), 5)


@pytest.fixture
def server_ssl_context(tmp_path) -> ssl.SSLContext:
    from heralding.misc import certs

    pem = tmp_path / "test.pem"
    cert, key = certs.generate_self_signed_cert("US", None, None, None, None, "localhost", 1, 1)
    pem.write_bytes(cert + key)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(pem))
    return ctx


@pytest.fixture
def client_ssl_context() -> ssl.SSLContext:
    # The honeypot presents a self-signed certificate; tests only need the handshake.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

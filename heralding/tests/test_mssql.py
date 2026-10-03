import asyncio

import pytds
import pytest

from heralding.capabilities import mssql
from heralding.tests.conftest import make_options


async def test_login_is_refused_and_logged(serve, sink):
    host, port = await serve(mssql.Mssql(make_options()))

    def run():
        with pytest.raises(pytds.Error) as excinfo:  # pytds maps 18456 to OperationalError
            pytds.connect(
                dsn=host,
                port=port,
                user="sa",
                password="P@ssw0rd!",
                database="master",
                login_timeout=5,
                timeout=5,
                appname="probe-app",
            )
        return str(excinfo.value)

    message = await asyncio.to_thread(run)
    assert "Login failed for user 'sa'" in message
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("sa", "P@ssw0rd!")
    assert attempt["protocol"] == "mssql"
    ended = await asyncio.to_thread(sink.wait_for_session_end, 1)
    aux = ended[0]["auxiliary_data"]
    assert aux["app_name"] == "probe-app"
    assert aux["database"] == "master"
    assert aux["client_hostname"]


@pytest.fixture
def tls_mssql(tmp_path):
    import ssl

    from heralding.misc import certs

    pem = tmp_path / "mssql.pem"
    cert, key = certs.generate_self_signed_cert(
        "", None, None, None, None, "SSL_Self_Signed_Fallback", 365
    )
    pem.write_bytes(cert + key)
    cap = mssql.Mssql(make_options())
    cap.starttls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cap.starttls_context.load_cert_chain(str(pem))
    return cap, str(pem)


@pytest.mark.parametrize("login_only", [True, False])
async def test_encrypted_login_is_captured(serve, sink, tls_mssql, login_only):
    cap, pem = tls_mssql
    host, port = await serve(cap)

    def run():
        with pytest.raises(pytds.Error) as excinfo:
            pytds.connect(
                dsn=host,
                port=port,
                user="sa",
                password="Encr7pted!",
                login_timeout=5,
                timeout=5,
                cafile=pem,  # pyOpenSSL client; certificate name is not the host
                validate_host=False,
                enc_login_only=login_only,
            )
        return str(excinfo.value)

    assert "Login failed for user 'sa'" in await asyncio.to_thread(run)
    attempt = (await asyncio.to_thread(sink.wait_for_auth, 1))[0]
    assert (attempt["username"], attempt["password"]) == ("sa", "Encr7pted!")
    aux = (await asyncio.to_thread(sink.wait_for_session_end, 1))[0]["auxiliary_data"]
    assert aux["tls_version"] == "TLSv1.2"
    assert aux["client_encryption"] == (0 if login_only else 1)


def test_server_answers_the_client_encryption_wish():
    from heralding.libs import tds

    assert tds.server_encryption(tds.ENCRYPT_OFF) == tds.ENCRYPT_OFF
    assert tds.server_encryption(tds.ENCRYPT_ON) == tds.ENCRYPT_ON
    assert tds.server_encryption(tds.ENCRYPT_REQ) == tds.ENCRYPT_ON
    assert tds.server_encryption(tds.ENCRYPT_NOT_SUP) == tds.ENCRYPT_NOT_SUP
    assert tds.server_encryption(None) == tds.ENCRYPT_NOT_SUP

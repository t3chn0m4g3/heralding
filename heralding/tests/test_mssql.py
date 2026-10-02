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
                server=host,
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

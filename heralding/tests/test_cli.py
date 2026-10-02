import asyncio
import os
import re
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import yaml

from heralding.tests.test_tpot_compat import FIXTURES

FORBIDDEN = (
    "Traceback",
    "RuntimeError",
    "ModuleNotFoundError",
    "OSError:",
    "Exception in callback",
    "Unhandled exception",
)


def _tpot_config(tmp_path):
    config = yaml.safe_load((FIXTURES / "tpot_heralding.yml").read_text())
    config["public_ip_as_destination_ip"] = False
    config["bind_host"] = "127.0.0.1"
    for key in ("session_csv_log_file", "session_json_log_file", "authentication_log_file"):
        name = Path(config["activity_logging"]["file"][key]).name
        config["activity_logging"]["file"][key] = str(tmp_path / name)
    caps = config["capabilities"]
    for cap in caps:
        caps[cap]["port"] = 0
    return config


def _start(tmp_path, config):
    cfg = tmp_path / "heralding.yml"
    cfg.write_text(yaml.safe_dump(config))
    log = tmp_path / "heralding.log"
    proc = subprocess.Popen(
        [sys.executable, "-m", "heralding.cli", "-c", str(cfg), "-l", str(log)],
        cwd=tmp_path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    return proc, log


def _wait_started(proc, log, needle="started vnc capability", timeout=30):
    deadline = time.monotonic() + timeout
    text = ""
    while time.monotonic() < deadline:
        text = log.read_text() if log.exists() else ""
        if needle in text.lower():
            return text
        if proc.poll() is not None:
            raise AssertionError(f"process exited early ({proc.returncode}):\n{text}")
        time.sleep(0.2)
    raise AssertionError(f"startup incomplete:\n{text}")


def _assert_clean(text):
    for bad in FORBIDDEN:
        assert bad not in text, f"{bad!r} found in log:\n{text}"


def test_sigint_clean_shutdown(tmp_path):
    proc, log = _start(tmp_path, _tpot_config(tmp_path))
    try:
        _wait_started(proc, log)
        os.kill(proc.pid, signal.SIGINT)
        assert proc.wait(timeout=15) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
    text = log.read_text()
    assert "Initializing Heralding version" in text
    assert "All tasks were stopped." in text
    _assert_clean(text)


def test_sigint_with_active_session_exits_promptly(tmp_path):
    config = _tpot_config(tmp_path)
    proc, log = _start(tmp_path, config)
    try:
        text = _wait_started(proc, log)
        port = int(re.search(r"Started telnet capability listening on port (\d+)", text)[1])

        async def client():
            from heralding.tests.test_telnet import _connect, _read_until

            reader, writer = await _connect("127.0.0.1", port)
            try:
                await _read_until(reader, writer, b"Username:")
                writer.write(b"eve\r\n")
                await writer.drain()
                await _read_until(reader, writer, b"Password:")
                started = time.monotonic()
                os.kill(proc.pid, signal.SIGINT)
                assert await asyncio.to_thread(proc.wait, timeout=10) == 0
                assert time.monotonic() - started < 10
            finally:
                writer.close()

        asyncio.run(client())
    finally:
        if proc.poll() is None:
            proc.kill()
    text = log.read_text()
    assert "All tasks were stopped." in text
    _assert_clean(text)
    sessions = (tmp_path / "log_session.json").read_text().splitlines()
    assert any(
        '"protocol": "telnet"' in line and '"session_ended": true' in line for line in sessions
    )


def test_unwritable_log_path_fails_fast_without_traceback(tmp_path):
    config = _tpot_config(tmp_path)
    config["activity_logging"]["file"]["authentication_log_file"] = str(
        tmp_path / "does-not-exist" / "auth.csv"
    )
    proc, log = _start(tmp_path, config)
    assert proc.wait(timeout=20) == 2
    text = log.read_text()
    assert "Could not open" in text
    _assert_clean(text)


def test_port_conflict_fails_without_traceback(tmp_path):
    config = _tpot_config(tmp_path)
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", config["capabilities"]["ftp"]["port"]))
    blocker.listen(1)
    config["capabilities"]["ftp"]["port"] = blocker.getsockname()[1]
    try:
        proc, log = _start(tmp_path, config)
        assert proc.wait(timeout=20) == 1
    finally:
        blocker.close()
    text = log.read_text()
    assert "Could not start" in text
    _assert_clean(text)

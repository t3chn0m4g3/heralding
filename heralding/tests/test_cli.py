import os
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


def _free_ports(n):
    socks = [socket.socket() for _ in range(n)]
    for s in socks:
        s.bind(("127.0.0.1", 0))
    ports = [s.getsockname()[1] for s in socks]
    for s in socks:
        s.close()
    return ports


def test_sigint_clean_shutdown(tmp_path):
    config = yaml.safe_load((FIXTURES / "tpot_heralding.yml").read_text())
    config["public_ip_as_destination_ip"] = False
    config["bind_host"] = "127.0.0.1"
    for key in ("session_csv_log_file", "session_json_log_file", "authentication_log_file"):
        name = Path(config["activity_logging"]["file"][key]).name
        config["activity_logging"]["file"][key] = str(tmp_path / name)
    caps = config["capabilities"]
    for cap, port in zip(caps, _free_ports(len(caps)), strict=True):
        caps[cap]["port"] = port
    cfg = tmp_path / "heralding.yml"
    cfg.write_text(yaml.safe_dump(config))
    log = tmp_path / "heralding.log"

    proc = subprocess.Popen(
        [sys.executable, "-m", "heralding.cli", "-c", str(cfg), "-l", str(log)],
        cwd=tmp_path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + 30
        text = ""
        while time.monotonic() < deadline:
            text = log.read_text() if log.exists() else ""
            if "started rdp capability" in text.lower():
                break
            if proc.poll() is not None:
                raise AssertionError(f"process exited early ({proc.returncode}):\n{text}")
            time.sleep(0.2)
        else:
            raise AssertionError(f"startup incomplete:\n{text}")
        os.kill(proc.pid, signal.SIGINT)
        assert proc.wait(timeout=15) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
    text = log.read_text()
    assert "Initializing Heralding version" in text
    assert "All tasks were stopped." in text
    for bad in FORBIDDEN:
        assert bad not in text, f"{bad!r} found in log:\n{text}"

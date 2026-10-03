# Copyright (C) 2017 Johnny Vestergaard <jkv@unixcluster.dk>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import asyncio
import ipaddress
import logging
import urllib.request

logger = logging.getLogger(__name__)

PUBLIC_IP_ENDPOINTS = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
)


async def cancel_all_pending_tasks(grace_seconds: float = 5.0) -> None:
    current = asyncio.current_task()
    pending = [t for t in asyncio.all_tasks() if t is not current and not t.done()]
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.wait(pending, timeout=grace_seconds)


def _fetch_text(url: str, timeout: float) -> str:
    if not url.startswith("https://"):
        raise ValueError("only https endpoints are allowed")
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8.5.0"})  # noqa: S310
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return resp.read(64).decode("ascii", "replace")


def get_public_ip(timeout: float = 5.0) -> str:
    """Blocking lookup with a timeout and fallbacks. Run it in a thread."""
    errors = []
    for url in PUBLIC_IP_ENDPOINTS:
        try:
            value = _fetch_text(url, timeout).strip()
            ipaddress.ip_address(value)
            return value
        except (OSError, ValueError) as exc:
            errors.append(f"{url} [{type(exc).__name__}] {exc}")
    raise RuntimeError("; ".join(errors))

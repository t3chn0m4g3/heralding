"""Persona: a coherent set of banners, versions and names the honeypot presents.

One persona is selected when the honeypot starts (config key ``persona``: ``random`` or a
profile name from ``personas.yml``). Capabilities ask :meth:`Persona.get` for values; an
explicit, non-empty value in the capability's config always wins (see
``HandlerBase.persona_value``).
"""

import json
import logging
import random
import re
from dataclasses import dataclass
from importlib import resources

import yaml

_FIELD = re.compile(r"\{(hostname|domain|netbios)\}")
logger = logging.getLogger(__name__)


def load_personas(path: str | None = None) -> dict:
    if path is None:
        text = resources.files("heralding").joinpath("personas.yml").read_text(encoding="utf-8")
    else:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    return yaml.safe_load(text)


def make_hostname(pattern: str, rng: random.Random, domain: str = "", roles=None) -> str:
    roles = roles or ["srv"]
    return (
        pattern.replace("{role}", str(rng.choice(roles)))
        .replace("{n1}", str(rng.randint(1, 9)))
        .replace("{n2}", f"{rng.randint(1, 99):02d}")
        .replace("{domain}", domain)
    )


@dataclass(frozen=True)
class Persona:
    name: str
    hostname: str
    domain: str
    netbios: str
    os_family: str
    values: dict
    cert_subject: dict

    @property
    def fqdn(self) -> str:
        return f"{self.hostname}.{self.domain}" if self.domain else self.hostname

    def _fmt(self, value):
        if not isinstance(value, str):
            return value
        return _FIELD.sub(lambda m: getattr(self, m.group(1)), value)

    def get(self, capability: str, key: str):
        value = (self.values.get(capability) or {}).get(key)
        if value in (None, ""):
            return None
        return self._fmt(value)


def _load_state(state_path):
    try:
        with open(state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and data.get("name") and data.get("hostname"):
            return data
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        logger.warning(
            "Ignoring unreadable persona state %s [%s] %s", state_path, type(exc).__name__, exc
        )
    return None


def _save_state(state_path, name, hostname):
    try:
        with open(state_path, "w", encoding="utf-8") as fh:
            json.dump({"name": name, "hostname": hostname}, fh)
    except OSError as exc:
        logger.warning(
            "Could not persist persona state %s [%s] %s", state_path, type(exc).__name__, exc
        )


def select_persona(
    config: dict | None, rng: random.Random | None = None, state_path: str | None = None
) -> Persona:
    """Pick the persona for this process.

    The identity (persona name + hostname) is persisted in `state_path` when given, so a
    honeypot that is restarted in the same working directory keeps looking like the same
    machine. It only changes when the operator sets a different `persona` in the config or
    deletes the state file.
    """
    rng = rng or random.SystemRandom()
    personas = load_personas()
    wanted = (config or {}).get("persona") or "random"
    if wanted != "random" and wanted not in personas:
        raise ValueError(f"unknown persona {wanted!r}; known: {', '.join(sorted(personas))}")

    state = _load_state(state_path) if state_path else None
    hostname = None
    if state and state["name"] in personas and (wanted == "random" or wanted == state["name"]):
        name, hostname = state["name"], state["hostname"]
    elif wanted == "random":
        name = rng.choice(sorted(personas))
    else:
        name = wanted
    raw = personas[name]
    domain = raw.get("domain") or ""
    if hostname is None:
        hostname = make_hostname(
            raw.get("hostname_pattern", "srv{n2}"), rng, domain, raw.get("roles")
        )
        if state_path:
            _save_state(state_path, name, hostname)
    netbios = (raw.get("netbios") or "").replace("{hostname}", hostname).upper()
    cert = {}
    for key, value in (raw.get("cert") or {}).items():
        value = value or ""
        cert[key] = value.replace("{hostname}", hostname).replace("{domain}", domain)
    return Persona(
        name=name,
        hostname=hostname,
        domain=domain,
        netbios=netbios,
        os_family=raw.get("os_family", "linux"),
        values=raw.get("capabilities") or {},
        cert_subject=cert,
    )

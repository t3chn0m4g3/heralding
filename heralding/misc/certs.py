"""Self-signed certificate generation (cryptography) for the TLS capabilities."""

import datetime
import hashlib
import json
import os
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Older configurations may use the literal string "None" for unset subject fields.
_UNSET = {None, "", "None", "none", "null"}


def is_unset(value) -> bool:
    return value in _UNSET


def generate_self_signed_cert(
    country,
    state,
    organization,
    locality,
    organizational_unit,
    common_name,
    valid_days,
    serial_number=None,
) -> tuple[bytes, bytes]:
    """Return (cert_pem, key_pem). RSA 2048, SHA-256, random serial unless given, backdated."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attrs = []
    for oid, value in (
        (NameOID.COUNTRY_NAME, country),
        (NameOID.STATE_OR_PROVINCE_NAME, state),
        (NameOID.LOCALITY_NAME, locality),
        (NameOID.ORGANIZATION_NAME, organization),
        (NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
        (NameOID.COMMON_NAME, common_name),
    ):
        if not is_unset(value):
            attrs.append(x509.NameAttribute(oid, str(value)))
    name = x509.Name(attrs)
    now = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
    # a freshly minted certificate is a fingerprint; pretend it is 1-11 months old
    not_before = now - datetime.timedelta(days=secrets.randbelow(300) + 30)
    serial = int(serial_number) if serial_number else x509.random_serial_number()
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=int(valid_days)))
    )
    if not is_unset(common_name) and common_name != "*":
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(str(common_name))]), critical=False
        )
    cert = builder.sign(key, hashes.SHA256())
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
    )


def ensure_cert(pem_path: str, cert_cfg: dict | None, persona_tag: str | None = None) -> str:
    """Create <pem_path> (cert + key, mode 0600) from the config block unless it exists.

    With a persona_tag, a marker file <pem_path>.persona records which persona the
    certificate belongs to; a different tag regenerates the certificate. A certificate
    without a marker (pre-2.0 installation) is kept and the marker is added.
    """
    marker = pem_path + ".persona"
    config_marker = pem_path + ".config"
    config_hash = hashlib.sha256(json.dumps(cert_cfg or {}, sort_keys=True).encode()).hexdigest()
    if os.path.isfile(pem_path) and os.path.isfile(config_marker):
        with open(config_marker, encoding="utf-8") as fh:
            if fh.read().strip() != config_hash:
                os.remove(pem_path)
                if os.path.isfile(marker):
                    os.remove(marker)
                os.remove(config_marker)
    if os.path.isfile(pem_path) and not os.path.isfile(config_marker):
        _write_marker(config_marker, config_hash)
    if os.path.isfile(pem_path):
        if persona_tag is None:
            return pem_path
        if not os.path.isfile(marker):
            _write_marker(marker, persona_tag)
            return pem_path
        with open(marker, encoding="utf-8") as fh:
            if fh.read().strip() == persona_tag:
                return pem_path
        os.remove(pem_path)
        os.remove(marker)
    cfg = cert_cfg or {}
    cert, key = generate_self_signed_cert(
        cfg.get("country"),
        cfg.get("state"),
        cfg.get("organization"),
        cfg.get("locality"),
        cfg.get("organizational_unit"),
        cfg.get("common_name", "*"),
        cfg.get("valid_days", 365),
        cfg.get("serial_number") or None,  # legacy "serial_number: 0" means "pick one"
    )
    fd = os.open(pem_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(cert)
        fh.write(key)
    if persona_tag is not None:
        _write_marker(marker, persona_tag)
    _write_marker(config_marker, config_hash)
    return pem_path


def _write_marker(marker: str, tag: str) -> None:
    with open(marker, "w", encoding="utf-8") as fh:
        fh.write(tag)

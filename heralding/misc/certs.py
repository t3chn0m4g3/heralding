"""Self-signed certificate generation (cryptography) for the TLS capabilities."""

import datetime
import os
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# T-Pot's dist config ships the literal string "None" for unset subject fields.
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


def ensure_cert(pem_path: str, cert_cfg: dict | None) -> str:
    """Create <pem_path> (cert + key, mode 0600) from the config block unless it exists."""
    if os.path.isfile(pem_path):
        return pem_path
    cfg = cert_cfg or {}
    cert, key = generate_self_signed_cert(
        cfg.get("country"),
        cfg.get("state"),
        cfg.get("organization"),
        cfg.get("locality"),
        cfg.get("organizational_unit"),
        cfg.get("common_name", "*"),
        cfg.get("valid_days", 365),
        cfg.get("serial_number") or None,  # T-Pot's "serial_number: 0" means "pick one"
    )
    fd = os.open(pem_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(cert)
        fh.write(key)
    return pem_path

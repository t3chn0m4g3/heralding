import datetime
import os
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from heralding.misc import certs

LEGACY_CERT_CFG = {
    "common_name": "*",
    "country": "US",
    "state": "None",
    "locality": "None",
    "organization": "None",
    "organizational_unit": "None",
    "valid_days": 365,
    "serial_number": 0,
}


def test_none_strings_are_unset(tmp_path):
    pem = certs.ensure_cert(str(tmp_path / "x.pem"), LEGACY_CERT_CFG)
    cert = x509.load_pem_x509_certificate(open(pem, "rb").read())
    names = {attr.oid._name for attr in cert.subject}
    assert names == {"countryName", "commonName"}
    assert isinstance(cert.signature_hash_algorithm, hashes.SHA256)
    assert cert.serial_number != 0
    assert cert.not_valid_before_utc < datetime.datetime.now(datetime.UTC) - datetime.timedelta(
        days=1
    )
    assert oct(os.stat(pem).st_mode & 0o777) == "0o600"


def test_pem_loads_into_ssl_context(tmp_path):
    pem = certs.ensure_cert(str(tmp_path / "x.pem"), LEGACY_CERT_CFG)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pem)  # raises if cert and key do not match


def test_existing_cert_is_kept(tmp_path):
    p = tmp_path / "x.pem"
    p.write_bytes(b"keep")
    os.chmod(p, 0o600)
    certs.ensure_cert(str(p), {"common_name": "*", "country": "US", "valid_days": 1})
    assert p.read_bytes() == b"keep"


def test_explicit_subject_and_san():
    cert_pem, _ = certs.generate_self_signed_cert(
        "DE", "Bavaria", "Example Org", "Munich", "IT", "mail.example.org", 30, None
    )
    cert = x509.load_pem_x509_certificate(cert_pem)
    assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == (
        "mail.example.org"
    )
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["mail.example.org"]
    assert cert.not_valid_after_utc - cert.not_valid_before_utc == datetime.timedelta(days=30)


def test_is_unset():
    assert certs.is_unset(None)
    assert certs.is_unset("None")
    assert certs.is_unset("")
    assert not certs.is_unset("US")


def test_persona_marker_written_and_cert_regenerated_on_change(tmp_path):
    from pathlib import Path

    p = tmp_path / "https.pem"
    first = certs.ensure_cert(str(p), {"common_name": "*"}, persona_tag="debian-12")
    assert (tmp_path / "https.pem.persona").read_text() == "debian-12"
    data1 = Path(first).read_bytes()
    certs.ensure_cert(str(p), {"common_name": "*"}, persona_tag="debian-12")
    assert Path(first).read_bytes() == data1  # unchanged
    certs.ensure_cert(str(p), {"common_name": "*"}, persona_tag="rhel-9")
    assert Path(first).read_bytes() != data1  # regenerated
    assert (tmp_path / "https.pem.persona").read_text() == "rhel-9"


def test_legacy_cert_without_marker_is_kept(tmp_path):
    p = tmp_path / "imaps.pem"
    p.write_bytes(b"legacy")
    certs.ensure_cert(str(p), {"common_name": "*"}, persona_tag="rhel-9")
    assert p.read_bytes() == b"legacy"
    assert (tmp_path / "imaps.pem.persona").read_text() == "rhel-9"


def test_marker_is_the_fqdn_not_the_persona_name(tmp_path):
    p = tmp_path / "https.pem"
    certs.ensure_cert(str(p), {"common_name": "*"}, persona_tag="web-07.internal")
    assert (tmp_path / "https.pem.persona").read_text() == "web-07.internal"


def test_explicit_certificate_configuration_change_regenerates_certificate(tmp_path):
    p = tmp_path / "https.pem"
    certs.ensure_cert(str(p), {"common_name": "old.example"}, persona_tag="host.example")
    original = p.read_bytes()
    certs.ensure_cert(str(p), {"common_name": "new.example"}, persona_tag="host.example")
    assert p.read_bytes() != original
    certificate = x509.load_pem_x509_certificate(p.read_bytes())
    assert (
        certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        == "new.example"
    )
    current = p.read_bytes()
    certs.ensure_cert(str(p), {"common_name": "new.example"}, persona_tag="host.example")
    assert p.read_bytes() == current

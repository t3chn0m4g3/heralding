"""Manual container probes using standard clients and synthetic credentials."""

import os
import smtplib
import sys
import uuid

import pymysql
from smbprotocol.connection import Connection
from smbprotocol.exceptions import LogonFailure
from smbprotocol.session import Session

host = sys.argv[1]
password = "AuditPass123"

with smtplib.SMTP(host, 25, local_hostname="audit.local", timeout=5) as client:
    client.ehlo()
    client.user, client.password = "cram-audit", password
    try:
        client.auth("CRAM-MD5", client.auth_cram_md5)
    except smtplib.SMTPAuthenticationError as exc:
        assert exc.smtp_code == 535

try:
    pymysql.connect(host=host, user="mysql-audit", password=password, connect_timeout=5)
except pymysql.err.OperationalError as exc:
    assert exc.args[0] == 1045

for level in (0, 3):
    os.environ["LM_COMPAT_LEVEL"] = str(level)
    connection = Connection(uuid.uuid4(), host, require_signing=False)
    try:
        connection.connect(timeout=5)
        session = Session(
            connection,
            username=f"CORP\\ntlm{level}-audit",
            password=password,
            require_encryption=False,
            auth_protocol="ntlm",
        )
        try:
            session.connect()
        except LogonFailure:
            pass
        else:
            raise AssertionError("SMB accepted authentication")
    finally:
        connection.disconnect()
print("SMTP CRAM-MD5, MySQL, NTLMv1 and NTLMv2 attempts sent and refused")

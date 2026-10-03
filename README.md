# Heralding

[![PyPI version](https://img.shields.io/pypi/v/heralding.svg)](https://pypi.python.org/pypi/Heralding/)

Sometimes you just want a simple honeypot that collects credentials, nothing more. Heralding is that
honeypot!

Supported protocols: ftp (with AUTH TLS), ftps, telnet, ssh, http, https, http_proxy, pop3, pop3s,
imap, imaps, smtp, smtps, submission, vnc, postgresql, mysql, mssql, rdp, socks5, redis, mqtt,
mqtts, ldap, ldaps, sip (UDP and TCP) and smb (NTLMv1/v2).

**Heralding 2.0 needs Python 3.14 or newer.** Dependencies are managed with
[uv](https://docs.astral.sh/uv/).
T-Pot deployment configuration and integration tests are maintained in the T-Pot repository.

## Installing

```shell
git clone https://github.com/johnnykv/heralding
cd heralding
uv sync                       # add --extra hpfeeds / --extra curiosum as needed
mkdir tmp && cd tmp
sudo ../.venv/bin/heralding   # or: uv run heralding -c myconfig.yml -l heralding.log
```

Heralding binds the configured ports, then drops to `nobody`/`nogroup` (configurable with
`user`/`group` in the config). Certificates, the SSH host key and `persona.state` are created in the
working directory on first start.

## Starting the honeypot

```text
2026-10-02 16:41:44,850 (root) Initializing Heralding version 2.0.0
2026-10-02 16:41:44,860 (heralding.reporting.file_sink) File logger: Using log_auth.csv to log authentication attempts in CSV format.
2026-10-02 16:41:44,861 (heralding.honeypot) Persona: debian-12 (mail8.lan)
2026-10-02 16:41:44,866 (heralding.honeypot) Started ftp capability listening on port 21
2026-10-02 16:41:44,874 (heralding.honeypot) Started http capability listening on port 80
...
2026-10-02 16:41:45,106 (heralding.honeypot) Started vnc capability listening on port 5900
```

Every capability can be switched off or moved to another port in `heralding.yml`.

## Persona

At start-up Heralding picks a *persona*: a coherent set of banners, server versions, host and domain
names and certificate subjects. The profiles live in `heralding/personas.yml` (`ubuntu-24.04`,
`debian-12`, `rhel-9`, `windows-server-2019`, `windows-server-2022`). The config key `persona`
selects one; `random` is the default. The choice is stored in `persona.state` in the working
directory and reused on the next start, so the honeypot keeps looking like the same machine.

Any banner, version or certificate field set explicitly in `heralding.yml` overrides the persona for
that capability.

## IPv6

Heralding listens on IPv4 and IPv6 by default (`bind_host: ["0.0.0.0", "::"]`). Without IPv6 on the
host, for example in a container on an IPv4-only network, the `"::"` entry is skipped with a warning.
Use `bind_host: 0.0.0.0` for IPv4 only; `"::"` alone listens on IPv6 only. Addresses are logged
without the `::ffff:` prefix. The per-source session limit counts an IPv6 /64 as one source.

## Viewing the collected data

Heralding writes three files: `log_session.json`, `log_auth.csv` and `log_session.csv`.

### log_session.json

All available information for a session, written as JSON Lines **after** the session has ended:
timestamps, authentication attempts and protocol specific details in `auxiliary_data`. Examples of
auxiliary data are the client's command lines for ftp, imap, pop3 and telnet (`commands`, at most 50,
`commands_truncated` when cut), the telnet client's terminal type, environment variables and window
size (`terminal_type`, `environment`, `window_size`), SSH client versions and offered public keys
(`publickey_attempts`), HTTP request headers, SOCKS5 auth methods, MQTT client ids and the RDP
domain.

```json
{
  "timestamp": "2026-10-02 08:29:09.019394",
  "duration": 9,
  "session_id": "4ba1fc0a-872c-46bb-a2f8-80c38453c74f",
  "source_ip": "192.0.2.10",
  "source_port": 52192,
  "destination_ip": "198.51.100.5",
  "destination_port": 22,
  "protocol": "ssh",
  "num_auth_attempts": 1,
  "auth_attempts": [
    {
      "timestamp": "2026-10-02 08:29:12.732530",
      "username": "rewt",
      "password": "PASSWORD",
      "auth_id": "0f3c0a1e-5a2b-4a36-9d3e-1f0b9a7c2d11",
      "password_hash": null,
      "method": "plaintext"
    }
  ],
  "session_ended": true,
  "auxiliary_data": {
    "client_version": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
    "recv_cipher": "aes128-ctr",
    "recv_mac": "umac-64-etm@openssh.com",
    "recv_compression": "none"
  }
}
```

### log_session.csv

One line per connection, written after the session has ended: timestamp, duration, addresses,
protocol and the number of authentication attempts.

```text
timestamp,duration,session_id,source_ip,source_port,destination_ip,destination_port,protocol,num_auth_attempts
2026-10-02 20:38:19.683713,16,0841e3aa-241b-4da0-b85e-e5a5524cc836,192.0.2.10,53161,198.51.100.5,23,telnet,3
```

### log_auth.csv

One line per authentication attempt, written as soon as the credentials arrive. The first ten
columns are stable for external consumers. New columns are only ever
appended. `password_hash` is set for protocols that never send the password in clear (for example
MySQL, VNC, SMTP CRAM-MD5, SIP, SMB, RDP NLA and LDAP NTLM) and uses formats that hashcat or John the Ripper understand.

```text
timestamp,auth_id,session_id,source_ip,source_port,destination_ip,destination_port,protocol,username,password,password_hash
2026-10-02 20:35:02.258198,3f1c…,6c7d653f-…,192.0.2.10,51551,198.51.100.5,23,telnet,bond,james,
```

**Warning:** values are written exactly as the client sent them. A "password" like
`=HYPERLINK("http://evil")` ends up verbatim in the CSV. Do not open these files in a spreadsheet
application with formula evaluation enabled.

### LDAP NTLM

With a Windows persona the LDAP capability behaves like Active Directory: NTLM binds over Sicily
(ldap3, impacket) and SASL GSS-SPNEGO are answered with a challenge, and the NTLMv1/v2 response is
logged in `password_hash`. Failed binds carry AD's `AcceptSecurityContext error, data 52e` message.
OpenLDAP and 389 personas refuse Sicily as those servers do.

### MSSQL encryption

Like SQL Server with its self-signed certificate (`CN=SSL_Self_Signed_Fallback`), Heralding answers
the client's PRELOGIN encryption wish: clients asking for login-only encryption get TLS for the
LOGIN7 packet, clients requiring encryption get a fully encrypted connection, others stay in
plaintext. Credentials are captured in all three cases; `tls_version` and `client_encryption` are
session metadata. TLS is limited to 1.2, as SQL Server does with TDS 7.x. TDS 8 (strict
encryption, TLS before PRELOGIN) is not supported.

### RDP authentication

TLS-only RDP captures the username, password and domain from Client Info. NLA/CredSSP
captures NTLMv1/v2 challenge-response material in `password_hash`, with an empty `password`.
The domain, workstation, TLS version and selected security mode are session metadata.
NLA attempts receive `STATUS_LOGON_FAILURE` after capture; Heralding never opens a desktop.
Kerberos-only and Remote Credential Guard authentication are unsupported.

RDP defaults to a TLS 1.2 maximum for client compatibility. Set
`protocol_specific_data.tls_max_version: TLSv1_3` to allow TLS 1.3 explicitly.
An explicit minimum of TLS 1.3 also raises the default maximum to TLS 1.3.
The startup log reports the effective range. Other protocols keep their own TLS settings.

The MCS user channel is allocated after the client's static channels to avoid overlapping
IDs. Session metadata records the channel count, user channel and joined channels.
Windows App 11.4.1 (3092) on macOS was confirmed to capture plaintext credentials through
its TLS-only fallback. Its initial NLA connection ended before sending authentication data;
this does not establish NLA compatibility for that app. Error 0x204 can remain after capture
because Heralding ends the connection without establishing a desktop.

Self-signed certificate warnings are expected. If a client disconnects before sending
credentials, its session can contain `rdp_requested_protocols` and `rdp_handshake_error`;
there is no authentication row for credentials that the client never transmitted.
CredSSP framing and failure responses follow Microsoft's
[MS-CSSP specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685).

## Docker

### Docker Compose

From this checkout, start the standalone deployment with Docker Compose:

```shell
docker compose up --build -d
docker compose logs -f heralding
docker compose exec heralding tail -f /var/log/heralding/log_auth.csv
```

[docker-compose.yml](docker-compose.yml) builds the local Dockerfile and publishes all 27 capabilities,
including SIP over TCP and UDP. The service runs as the image's non-root user with a
read-only root filesystem. Docker-managed volumes keep logs, certificates, the SSH host
key and `persona.state` across container recreation; host directories and ownership
changes are not needed. `docker compose down` retains these volumes; `down -v` deletes them.

Each service uses its standard host port, for example `21:21` for FTP and `22:22`
for SSH. SIP publishes both TCP and UDP on port 5060. To change a host port, edit
the left side of its mapping in `docker-compose.yml`, for example `2222:22`.

The image's default configuration is used. To customize capabilities, copy it with
`docker compose cp heralding:/etc/heralding/heralding.yml ./heralding.local.yml`, edit it,
then create an ignored `docker-compose.override.yml`:

```yaml
services:
  heralding:
    volumes:
      - ./heralding.local.yml:/etc/heralding/heralding.yml:ro
```

Keep file logging paths under `/var/log/heralding` in the custom configuration and run
`docker compose up -d` to apply it. Compose uses the override file automatically.

### Docker CLI

```shell
docker build -t heralding .
mkdir -p log
sudo chown 2000:2000 log
docker run --read-only --tmpfs /tmp/heralding:uid=2000,gid=2000 \
  -v "$PWD/log:/var/log/heralding" -p 2121:21 -p 2222:22 heralding
tail log/log_auth.csv
```

The image runs as uid 2000 with a read-only root filesystem. Logs go to `/var/log/heralding`;
the authentication log is `log_auth.csv`, matching the standalone defaults.
The mounted log directory must be writable by uid 2000. Deployment-specific names and
configuration belong in the consuming project's image and configuration.

## Running the tests

```shell
uv sync
uv run ruff check && uv run ruff format --check
uv run pytest --cov
```

Tests use standard clients for every protocol (stdlib clients, asyncssh, pymysql, psycopg,
redis-py, paho-mqtt, ldap3, python-tds, pyVoIP, python-socks, vncdotool, telnetlib3, smbprotocol). RDP logins are checked
manually with `xfreerdp`; CredSSP/NTLM capture uses automated pyspnego client tests.
The reproducible container commands are in [tools/validation](tools/validation/README.md).

## Pcaps

Want a separate pcap for each Heralding session? Take a look at the
[Curiosum](https://github.com/johnnykv/curiosum) project and enable the curiosum sink in
`heralding.yml` (`uv sync --extra curiosum`).

## Submitting code

Code is formatted and linted with [ruff](https://docs.astral.sh/ruff/) (`uv run ruff format`,
`uv run ruff check`). CI runs the same checks plus the test suite.

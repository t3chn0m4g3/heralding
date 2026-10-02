# Heralding

[![PyPI version](https://img.shields.io/pypi/v/heralding.svg)](https://pypi.python.org/pypi/Heralding/)

Sometimes you just want a simple honeypot that collects credentials, nothing more. Heralding is that
honeypot!

Supported protocols: ftp (with AUTH TLS), ftps, telnet, ssh, http, https, http_proxy, pop3, pop3s,
imap, imaps, smtp, smtps, submission, vnc, postgresql, mysql, mssql, rdp, socks5, redis, mqtt,
mqtts, ldap, ldaps and sip (UDP and TCP).

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

`bind_host` accepts a list, for example `["0.0.0.0", "::"]`. `"::"` alone listens on IPv6 only.
Addresses are logged without the `::ffff:` prefix.

## Viewing the collected data

Heralding writes three files: `log_session.json`, `log_auth.csv` and `log_session.csv`.

### log_session.json

All available information for a session, written as JSON Lines **after** the session has ended:
timestamps, authentication attempts and protocol specific details in `auxiliary_data`. Examples of
auxiliary data are the client's command lines for ftp, imap, pop3 and telnet (`commands`, at most 50,
`commands_truncated` when cut), SSH client versions and offered public keys
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
columns are fixed; T-Pot's logstash and ewsposter read them by position. New columns are only ever
appended. `password_hash` is set for protocols that never send the password in clear (for example
MySQL, VNC, SMTP CRAM-MD5 and SIP) and uses formats that hashcat or John the Ripper understand.

```text
timestamp,auth_id,session_id,source_ip,source_port,destination_ip,destination_port,protocol,username,password,password_hash
2026-10-02 20:35:02.258198,3f1c…,6c7d653f-…,192.0.2.10,51551,198.51.100.5,23,telnet,bond,james,
```

**Warning:** values are written exactly as the client sent them. A "password" like
`=HYPERLINK("http://evil")` ends up verbatim in the CSV. Do not open these files in a spreadsheet
application with formula evaluation enabled.

## Docker

```shell
docker build -t heralding .
docker run --read-only --tmpfs /tmp/heralding:uid=2000,gid=2000 \
  -v "$PWD/log:/var/log/heralding" -p 2121:21 -p 2222:22 heralding
tail log/auth.csv
```

The image runs as uid 2000 with a read-only root filesystem. Logs go to `/var/log/heralding`.

## Running the tests

```shell
uv sync
uv run ruff check && uv run ruff format --check
uv run pytest
```

Tests use standard clients for every protocol (stdlib clients, asyncssh, pymysql, psycopg,
redis-py, paho-mqtt, ldap3, python-tds, pyVoIP, python-socks, vncdotool). RDP logins are checked
manually with `xfreerdp`.

## Pcaps

Want a separate pcap for each Heralding session? Take a look at the
[Curiosum](https://github.com/johnnykv/curiosum) project and enable the curiosum sink in
`heralding.yml` (`uv sync --extra curiosum`).

## Submitting code

Code is formatted and linted with [ruff](https://docs.astral.sh/ruff/) (`uv run ruff format`,
`uv run ruff check`). CI runs the same checks plus the test suite.

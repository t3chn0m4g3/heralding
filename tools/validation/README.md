# Local container validation

These are manual checks from the completion audit, separate from pytest. All accounts and
passwords in these examples are synthetic. The network below has no external routing and
no host ports are published.

## Images and Linux tests

Run from the Heralding checkout:

```sh
docker build -t heralding:2.0-dev .
docker build -t heralding:validation-tools tools/validation
docker build -f tools/validation/Dockerfile.tests -t heralding:linux-tests tools/validation
docker run --rm -v "$PWD:/src:ro" heralding:linux-tests
```

Deployment-specific T-Pot checks and source builds are maintained in the T-Pot repository's
`docker/heralding/validation/` directory.

## Isolated server

Create a temporary audit directory (use an absolute path), a writable `log/` subdirectory,
and a copy of `heralding/heralding.yml` with `public_ip_as_destination_ip: false`,
`persona: windows-server-2022`, and file logging paths below `/var/log/heralding/`.
Set `audit_dir` to that directory. Logs are written by uid 2000.

```sh
docker network create --internal heralding-audit
docker run -d --name heralding-audit-server --network heralding-audit \
  --read-only --tmpfs /tmp/heralding:uid=2000,gid=2000 \
  -v "$audit_dir/config.yml:/etc/heralding/heralding.yml:ro" \
  -v "$audit_dir/log:/var/log/heralding" heralding:2.0-dev
```

## Standard clients

Authentication is refused. Check the server's log_auth.csv and log_session.json as the success
criterion; authentication-error exit codes from clients are expected.

```sh
docker run --rm --network heralding-audit heralding:validation-tools \
  timeout 12 xvfb-run -a xfreerdp /v:heralding-audit-server /u:rdp-audit \
  /p:AuditPass123 /d:CORP /sec:tls /cert:ignore /log-level:WARN
docker run --rm --network heralding-audit heralding:validation-tools \
  smbclient -L //heralding-audit-server -U 'CORP\smb-audit%AuditPass123'
docker run --rm --network heralding-audit heralding:validation-tools \
  hydra -l hydra-audit -p AuditPass123 -t 1 heralding-audit-server ftp
docker run --rm --network heralding-audit heralding:validation-tools \
  hydra -p AuditPass123 -t 1 heralding-audit-server vnc
docker run --rm --network heralding-audit heralding:validation-tools \
  sipsak --transport=tcp -U -s sip:sip-format-audit@heralding-audit-server \
  --auth-username=sip-format-audit -a AuditPass123
docker run --rm --network heralding-audit heralding:validation-tools \
  nmap -sV --version-light -Pn -p21,22,25,80,389,445,1433,1883,3389,5060,6379,8080 heralding-audit-server
docker run --rm --network heralding-audit -v "$PWD/tools/validation:/probes:ro" \
  heralding:validation-tools python /probes/client_logins.py heralding-audit-server
```

Repeat sipsak with `--transport=udp`. FreeRDP's `+enforce-tlsv1_2` selects TLS 1.2.
For TLS 1.0, start a second server with the same mounts plus
`-v "$PWD/tools/validation/tls10_server.py:/probes/tls10_server.py:ro"` and command
`python /probes/tls10_server.py -c /etc/heralding/heralding.yml -l /var/log/heralding/tls10.log`.
This fixture sets only the RDP context's maximum to TLS 1.0. Run FreeRDP against that
container with `/tls-seclevel:0`. Verify `auxiliary_data.tls_version` in the session log.
The first server defaults to TLS 1.3 with this client. Removing its `rdp.pem` after startup
and repeating FreeRDP verifies that the loaded context survives file removal.

## Credential material

Copy only the `password_hash` value from synthetic log_auth.csv rows to individual hash files.
A wordlist containing the single known password `AuditPass123` verifies the export.
Use `hashcat --potfile-path /audit/audit.pot` in the tool container, with the audit directory
mounted at `/audit`. Modes: NTLMv1 5500, NTLMv2 5600, CRAM-MD5 10200, MySQL 11200, SIP 11400.
For example:

```sh
docker run --rm -v "$audit_dir:/audit" heralding:validation-tools \
  hashcat -m 11400 /audit/sip.hash /audit/passwords.txt \
  --potfile-path /audit/audit.pot --outfile /audit/sip.result --quiet
```

VNC exports the John `$vnc$` format; the standard-client wordlist tests verify its response.
Hashcat 6.2.6 in this image has no VNC module.

## Cleanup

```sh
docker stop --signal SIGINT heralding-audit-server
docker rm heralding-audit-server
docker network rm heralding-audit
```

Remove any additional TLS server before removing the network.

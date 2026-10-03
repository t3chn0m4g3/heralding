# Changelog

## 2.0.0 (unreleased)

Requires Python 3.14. See README.md for installation, protocol limits and validation commands.

- Packaging with `pyproject.toml` and uv; `setup.py`, `requirements*.txt` and Travis removed.
- Runs on Python 3.14 (`asyncio.run`, aware UTC timestamps, no removed stdlib APIs).
- New reporting pipeline: one thread per sink, bounded queues, never blocks the event loop.
  hpfeeds and curiosum are optional extras.
- Hardening: session limits (global and per IP), read limits, no tracebacks in the log for
  client errors, bounded telnet input, prompt shutdown with connected clients.
- Personas: coherent banners, versions, host names and certificate subjects; explicit config
  values win.
- Certificates with `cryptography` (SHA-256, random serial, mode 0600).
- RDP supports TLS 1.0 to 1.3, with a default maximum of TLS 1.2 and an explicit TLS 1.3 override.
- RDP allocates a user channel after the static channels and handles both PER length forms;
  Windows App 11.4.1 on macOS was verified to log credentials through its TLS-only fallback.
- RDP NLA/CredSSP captures NTLM challenge responses and explicitly refuses authentication;
  generic TLS-only clients retain plaintext credential capture.
- IPv6 listeners, auxiliary data with client command lines and SSH public-key attempts.
- New services: redis, mqtt, mqtts, http_proxy, submission (STARTTLS), ftps and AUTH TLS on ftp,
  ldap, ldaps, mssql, sip (UDP and TCP), smb (SMB2 with NTLMv1/v2).
- Docker image on pinned `python:3.14-alpine`, non-root, read-only root filesystem.
- Completion fixes: bounded BER nesting and UDP lifecycles, buffered STARTTLS plaintext
  discarded, startup TLS contexts, certificate regeneration on configuration edits,
  RDP channel negotiation, persistent SIP TCP and corrected Hashcat SIP export.
- Review fixes: UDP pseudo-sessions have their own pool, the per-source limit counts an IPv6 /64
  as one source, and SIP over UDP only logs credentials whose nonce was sent to that source.
  `bind_host` defaults to IPv4 and IPv6 and skips `::` on hosts without IPv6.
- Credential capture: IMAP AUTHENTICATE LOGIN and ID, IMAP literals of mixed kinds, POP3 CAPA and
  AUTH PLAIN; the VNC hash is logged even when cracking is busy or the session times out.
- Fingerprints: Windows-like NTLM challenges (NetBIOS domain, version, timestamp), HTTP/1.1 with
  Apache, nginx or IIS pages, MySQL/MariaDB greetings per version, ProFTPD/vsftpd/IIS FTP and
  Postfix/Exchange SMTP wording, STARTTLS on port 25, POP3 CRLF, LDAP rootDSE per server, OpenSSH
  host keys and algorithm lists, SMB 3.0/3.0.2.
- Telnet records the client's terminal type, environment variables and window size.
- MSSQL answers the client's encryption wish like SQL Server (login-only or full TLS inside TDS,
  certificate `CN=SSL_Self_Signed_Fallback`), so clients that require encryption, such as ODBC
  Driver 18, also send their login.
- Standard clients across the suite; optional sinks and privilege changes tested.
  The actual hpfeeds3 client uses bounded socket I/O and a single connection attempt;
  library authentication and publishing are checked against a local test broker.
- T-Pot integration adds only free ports and accepts both SOCKS5 reply versions.
- Downstream T-Pot fixtures, integration probes and build scripts live in T-Pot's repository;
  standalone Docker logging retains Heralding's generic filenames.
- Behaviour changes: SOCKS5 replies follow RFC 1929; MySQL logins have an empty `password` and the
  challenge material in `password_hash`; VNC `password_hash` is a string.

## 1.0.7 (2020-12-27)

- Added custom POP3 banner (#143)
- Disabled RDP until we have an stable implementation.
- Various minor fixes and improvements

## 1.0.6 (2019-10-12)

- Added RDP capability (#25)
- Added MySQL capability (#76)
- Fixed HPFeeds bug (#123)
- Added basic password cracker
- Various minor fixes and improvements

## 1.0.5 (2019-04-18)

- Fixed asynssh issue (#111)

## 1.0.4 (2019-04-13)

- Added logging for auxiliary data for socks5, http and ssh (#85, #93, #95, #100)
- Added mysql capability (#95)
- Various fixes

## 1.0.3 (2018-11-20)

- Get destination ip from socket (#88)

## 1.0.2 (2018-09-10)

- HPFeeds issue fixed (#86, #87)

## 1.0.1 (2018-04-27)

- Socks5 capability added (#72)
- Added feature that allows pcap recording of session (Curiosum integration)
- Various minor fixes and improvements

## 1.0.0 (2017-12-28)

- Added VNC support (#68)
- New logging scheme (log_session.csv and log_auth.csv)
- Various minor fixes and improvements

## 0.2.4 (2017-12-3)

 - Fixed issue with MANIFEST.IN (#69)

## 0.2.3 (2017-12-3)

 - Added requirements-test.txt to MANIFEST.IN (#69)

## 0.2.2 (2017-10-19)

 - Added PostgreSQL support.
 - Added preliminary HPFriends support.

## 0.2.1 (2017-08-23)

 - Gevent replaced with asyncio
 - Various fixes

## 0.2.0 (2017-06-23)

 - Heralding converted to Python 3

## 0.1.17 (2017-06-20):

 - NOTICE:  This will be the last python 2 version of Heralding. All
            future versions will be Python 3.
 - Imap capability added

## 0.1.16 (2017-04-25):

 - Added ability to customize SSH banner
 - Fixed issue with encoding in CSV logger (#17)
 - Fixed issue when no shared ciphers found (#22)

## 0.1.15 (2016-10-31):

 - improvements to logger shutdown flow

## 0.1.14 (2016-08-17):

 - fixed premature ending of SSH sessions

## 0.1.13 (2016-05-20):

 - fixed decoding issue in smtp capability

## 0.1.12 (2016-05-15):

 - https and pop3s fixed and enabled by default

## 0.1.11 (2016-05-6):

 - Fixed bug that involved source_port not getting logged in CSV files

## 0.1.10 (2016-04-17):

 - Application will now be taken down if a logger fails

## 0.1.9 (2016-04-15):

 - Fixed typo in CSV reporter (souce_port -> source_port)

## 0.1.8 (2016-04-08):

 - Application will now exit if a capability cannot bind to a port
 - Added option to lookup public ip

## 0.1.7 (2016-04-03):

 - Configurable timeouts

## 0.1.6 (2016-04-03):

 - Fixed issue with sessions not getting closed
 - Introduced hard limit on number of concurrent sessions

## 0.1.5 (2016-04-03):

 - Added some debug logging

## 0.1.4 (2016-04-02):

 - Added ZMQ logger
 - Added auth_id to file logger

## 0.1.3 (2016-03-20):

 - Fixed CSV logging issue

## 0.1.2 (2016-03-19):

 - Fixed issue where config file was not included in module

## 0.1.1 (2016-03-18):

 - Minor build update

## 0.1.0 (2016-03-18):

 - Support for the following protocols: SSH, telnet, smtp, ftp, http, pop3
 - Stripped away unneeded components from the Beeswarm project (https://github.com/honeynet/beeswarm)

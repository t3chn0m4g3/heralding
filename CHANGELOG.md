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
- RDP works again with TLS 1.0 to 1.3.
- IPv6 listeners, auxiliary data with client command lines and SSH public-key attempts.
- New services: redis, mqtt, mqtts, http_proxy, submission (STARTTLS), ftps and AUTH TLS on ftp,
  ldap, ldaps, mssql, sip (UDP and TCP), smb (SMB2 with NTLMv1/v2).
- Docker image on pinned `python:3.14-alpine`, non-root, read-only root filesystem.
- Completion fixes: bounded BER nesting and UDP lifecycles, buffered STARTTLS plaintext
  discarded, startup TLS contexts, certificate regeneration on configuration edits,
  RDP channel negotiation, persistent SIP TCP and corrected Hashcat SIP export.
- Standard clients across the suite; optional sinks and privilege changes tested.
  The actual hpfeeds3 client uses bounded socket I/O and a single connection attempt;
  library authentication and publishing are checked against a local test broker.
- T-Pot integration adds only free ports and accepts both SOCKS5 reply versions.
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

Heralding |version badge|
=========================

.. |version badge| image:: https://img.shields.io/pypi/v/heralding.svg
   :target: https://pypi.python.org/pypi/Heralding/
   
   
About
-----

Sometimes you just want a simple honeypot that collects credentials, nothing more. Heralding is that honeypot!
Currently the following protocols are supported: ftp, telnet, ssh, http, https, pop3, pop3s, imap, imaps, smtp, smtps, vnc, postgresql, mysql, rdp, socks5, redis, mqtt, mqtts and http_proxy.

**You need Python 3.14 or higher.** Dependencies are managed with `uv <https://docs.astral.sh/uv/>`_.

Starting the honeypot
-----------------------

.. code-block:: shell

   2019-04-14 13:10:11,854 (root) Initializing Heralding version 1.0.4
   2019-04-14 13:10:11,879 (heralding.reporting.file_logger) File logger: Using log_auth.csv to log authentication attempts in CSV format.
   2019-04-14 13:10:11,879 (heralding.reporting.file_logger) File logger: Using log_session.csv to log unified session data in CSV format.
   2019-04-14 13:10:11,879 (heralding.reporting.file_logger) File logger: Using log_session.json to log complete session data in JSON format.
   2019-04-14 13:10:11,880 (heralding.honeypot) Started Pop3 capability listening on port 110
   2019-04-14 13:10:11,882 (heralding.honeypot) Started Pop3S capability listening on port 995
   2019-04-14 13:10:11,883 (heralding.honeypot) Started smtp capability listening on port 25
   2019-04-14 13:10:11,883 (heralding.honeypot) Started Http capability listening on port 80
   2019-04-14 13:10:11,885 (heralding.honeypot) Started https capability listening on port 443
   2019-04-14 13:10:11,885 (heralding.honeypot) Started Vnc capability listening on port 5900
   2019-04-14 13:10:11,885 (heralding.honeypot) Started Telnet capability listening on port 23
   2019-04-14 13:10:11,886 (heralding.honeypot) Started ftp capability listening on port 21
   2019-04-14 13:10:11,886 (heralding.honeypot) Started Imap capability listening on port 143
   2019-04-14 13:10:11,886 (heralding.honeypot) Started MySQL capability listening on port 3306
   2019-04-14 13:10:11,887 (heralding.honeypot) Started Socks5 capability listening on port 1080
   2019-04-14 13:10:11,946 (asyncssh) Creating SSH server on 0.0.0.0, port 2222
   2019-04-14 13:10:11,946 (heralding.honeypot) Started SSH capability listening on port 2222
   2019-04-14 13:10:11,946 (heralding.honeypot) Started PostgreSQL capability listening on port 5432
   2019-04-14 13:10:11,947 (heralding.honeypot) Started Imaps capability listening on port 993


Persona
-------

At start-up Heralding picks a *persona*, a coherent set of banners, server versions, host and
domain names and certificate subjects (``heralding/personas.yml``: ``ubuntu-24.04``, ``debian-12``,
``rhel-9``, ``windows-server-2019``, ``windows-server-2022``). The config key ``persona`` selects one
(``random`` is the default) and the choice is logged::

  Persona: ubuntu-24.04 (web-75.internal)

Any banner, version or certificate field set explicitly in ``heralding.yml`` overrides the persona
for that capability, so a fixed configuration (like T-Pot's) behaves exactly as before.

IPv6
----

``bind_host`` accepts a list, e.g. ``["0.0.0.0", "::"]``. Addresses are logged without the
``::ffff:`` prefix of IPv4-mapped IPv6 sockets.

Viewing the collected data
--------------------------

Heralding logs relevant data in three files, log_session.json, log_auth.csv and log_session.csv.

**log_session.json**

This log file contains all available information for a given activity to the honeypot. ``auxiliary_data`` holds protocol specific details: the client's command lines for ftp, imap, pop3 and telnet (``commands``, at most 50, ``commands_truncated`` when cut), SSH public keys offered (``publickey_attempts`` with type and SHA-256 fingerprint), HTTP request headers, SOCKS5 auth methods and RDP domain/TLS version. This included timestamp, authentication attempts and protocol specific information (auxiliary data) - and a bunch of other information. Be aware that the log entry for a specific session will appear in the log file **after** the session has ended. The format is jsonlines.

.. code-block:: json

   {  
     "timestamp":"2019-04-13 08:29:09.019394",
     "duration":9,
     "session_id":"4ba1fc0a-872c-46bb-a2f8-80c38453c74f",
     "source_ip":"127.0.0.1",
     "source_port":52192,
     "destination_ip":"127.0.0.1",
     "destination_port":2222,
     "protocol":"ssh",
     "num_auth_attempts":2,
     "auth_attempts":[  
       {  
         "timestamp":"2019-04-13 08:29:12.732530",
         "username":"rewt",
         "password":"PASSWORD"
       },
       {  
         "timestamp":"2019-04-13 08:29:15.686619",
         "username":"rewt",
         "password":"P@ssw0rd12345"
       },
     ],
     "session_ended":true,
     "auxiliary_data":{  
       "client_version":"SSH-2.0-OpenSSH_7.7p1 Ubuntu-4ubuntu0.3",
       "recv_cipher":"aes128-ctr",
       "recv_mac":"umac-64-etm@openssh.com",
       "recv_compression":"none"
     }
   }


**log_session.csv**

This log file contains entries for all connections to the honeypot. The data includes timestamp, duration, IP information and the number of authentication attempts. Be aware that the log entry for a specific session will appear in the log file **after** the session has ended. 

.. code-block:: shell

 $ tail log_session.csv
 timestamp,duration,session_id,source_ip,source_port,destination_ip,destination_port,protocol,auth_attempts
 2017-12-26 20:38:19.683713,16,0841e3aa-241b-4da0-b85e-e5a5524cc836,127.0.0.1,53161,,23,telnet,3
 2017-12-26 22:17:33.140742,6,d20c30c1-6765-4ab5-9144-a8be02385018,127.0.0.1,55149,,21,ftp,1
 2017-12-26 22:17:48.088281,0,e0f50505-af93-4234-b82c-5477d8d88546,127.0.0.1,55151,,22,ssh,0
 2017-12-26 22:18:06.284689,0,6c7d653f-d02d-4717-9973-d9b2e4a41d24,127.0.0.1,55153,,22,ssh,0
 2017-12-26 22:18:13.043327,30,f3af2c8c-b63f-4873-ac7f-28c73b9e3e92,127.0.0.1,55155,,22,ssh,3

**log_auth.csv**

This log file contains one line per authentication attempt. Log entries appear as soon as the credentials have been transmitted. The first ten columns are fixed (T-Pot's logstash and ewsposter parse them by position); ``password_hash`` carries challenge/response material in a hashcat/John-compatible format when the protocol never sends the password in clear (MySQL, VNC, SMTP CRAM-MD5), new columns are only ever appended.

.. code-block:: shell

  $ tail log_auth.csv
  timestamp,auth_id,session_id,source_ip,source_port,destination_ip,destination_port,protocol,username,password,password_hash
  2026-10-01 20:35:02.258198,3f1c...,6c7d653f-...,192.168.2.129,51551,10.0.0.5,23,telnet,bond,james,
  2026-10-01 20:35:09.658593,9a0b...,6c7d653f-...,192.168.2.129,51551,10.0.0.5,23,telnet,clark,P@SSw0rd123,
  2026-10-01 20:36:12.504483,77de...,f3af2c8c-...,192.168.2.129,53431,10.0.0.5,3306,mysql,root,,$mysqlna$1a2b...*9f8e...

**Warning:** values are written exactly as the attacker sent them. A "password" like ``=HYPERLINK("http://evil")`` ends up verbatim in the CSV. Do not open these files in a spreadsheet application with formula evaluation enabled.


Installing Heralding
---------------------

Heralding uses `uv <https://docs.astral.sh/uv/>`_ and needs Python 3.14 or newer.

.. code-block:: shell

  git clone https://github.com/johnnykv/heralding
  cd heralding
  uv sync                       # add --extra hpfeeds / --extra curiosum as needed
  mkdir tmp && cd tmp
  sudo ../.venv/bin/heralding   # or: uv run heralding -c myconfig.yml -l heralding.log

Heralding binds the configured ports, then drops to ``nobody``/``nogroup`` (configurable with
``user``/``group`` in the config). Certificates and the SSH host key are created in the working
directory on first start.

Running the tests
-----------------

.. code-block:: shell

  uv sync
  uv run ruff check && uv run ruff format --check
  uv run pytest

Docker Build
-------------
1.Checkout the code:

.. code-block:: shell

  cd ~
  git clone https://github.com/johnnykv/heralding.git
  cd heralding

2.Build new Docker image and run it (Http localhost expose example of port 80 to localhost:8080):

.. code-block:: shell

  sudo docker build -t heralding .

  sudo docker run -p 8080:80 heralding

Visit your application in a browser at http://localhost:8080

3.Check the log files:

.. code-block:: shell

  sudo docker ps


We need to copy the CONTAINER ID of our heralding image. Looking like 0beb67f1e92c.

.. code-block:: shell

  sudo docker exec -it 0beb67f1e92c bash


And now you are in the work directory, you can read the log files by typing cat and the name of the file. Example:

.. code-block:: shell

  cat log_auth.csv


Pcaps
-----

Want a seperate pcap for each heralding session? Sure, take a look at the Curisoum_ project. Make sure to enable Curisoum in Heralding.yml!

.. _Curisoum: https://github.com/johnnykv/curiosum


Submitting code
---------------

The project uses Chromium_ code style, please make sure to follow this before submitting. You can use tools like yapf to autoformat - the config file can be found at the root of the repo (.style.yapf).

.. _Chromium: https://chromium.googlesource.com/chromiumos/docs/+/master/styleguide/python.md

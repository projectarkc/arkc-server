#! /usr/bin/env python

import logging
import argparse
import json
from Crypto.PublicKey import RSA
from hashlib import sha1
from twisted.internet import reactor
from twisted.web.http import HTTPFactory
from twisted_connect_proxy.server import ConnectProxy
from coordinator import Coordinator


def start_proxy(port):
    """Start the internal HTTP proxy server.

    The proxy, which runs locally, serves as a middleware,
    i.e. the client handler forwards clients' requests to the proxy,
    and the proxy is reponsible for communicating with the target server.

    It is suggested that an external HTTP proxy is specified
    in place of the internal one,
    for performance and stability considerations.
    See command line arguments for detailed information.
    """
    factory = HTTPFactory()
    factory.protocol = ConnectProxy
    reactor.listenTCP(port, factory, interface="127.0.0.1")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start ArkC server.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show detailed logs")
    parser.add_argument('-c', '--config', dest = "config", default = 'config.json',
                        help="You must specify a configuration files. By default ./config.json is used.")

    # UDP activation messages are sent to this port to request the server to
    # initiate connections to a client
    #parser.add_argument("-up", "--udp-port", default=9000, type=int,
    #                    help="udp request listener port, 9000 by default")

    parser.add_argument('-ep', "--use-external-proxy", action="store_true",
                        help="use an external HTTPS proxy server running locally,\
                        e.g. polipo, for better performance.\
                        Fall back to in-built python proxy server otherwise.")
    #
    # Specify the port if an external proxy is used,
    # otherwise a proxy listening to this port will be created
    #parser.add_argument("-pp", "--proxy-port", default=8100, type=int,
    #                    help="local http proxy port, 8100 by default")

    # The server will connect the client behind Tor if this parameter
    # is specified
    #parser.add_argument("-tp", "--tor-port", default=None, type=int,
    #                    help="Tor port (9050), None to run without Tor")

    # The public and private keys
    # The public keys of trusted clients are pre-stored in server currently
    #parser.add_argument("-rc", "--remote-cert", type=str, required=True,
    #                    help="client public key (REQUIRED)",
    #                    dest="remote_cert_path")
    #parser.add_argument("-lc", "--local-cert", type=str, required=True,
    #                    help="server private key (REQUIRED)",
    #                    dest="local_cert_path")

    args = parser.parse_args()

    # mapping SHA1 to RSA key object, will be passed to coordinator
    # currently stores only one pair
    certs = dict()
    
    data = {}
                
        #Load json configuration file
    try:
        data_file = open(args.config)    
        data = json.load(data_file)
        data_file.close()
    except Exception as err:
        logging.error("Fatal error while loading configuration file.\n" + err)
        quit()

    try:
        with open(data["remote_cert_path"], "r") as f:
            remote_cert_txt = f.read()
            remote_cert = RSA.importKey(remote_cert_txt)
            certs[sha1(remote_cert_txt).hexdigest()] = remote_cert
    except Exception as err:
        print ("Fatal error while loading client certificate.")
        print (err)
        quit()

    try:
        with open(data["local_cert_path"], "r") as f:
            local_cert = RSA.importKey(f.read())
        if not local_cert.has_private():
            print("Fatal error, no private key included in local certificate.")
    except IOError as err:
        print ("Fatal error while loading local certificate.")
        print (err)
        quit()

    if args.verbose:
        logging.basicConfig(level=logging.INFO)

    if not args.use_external_proxy:    
        if "proxy_port" not in data:
            data["proxy_port"] = 8100
        start_proxy(data["proxy_port"])
    else:        
        if "proxy_port" not in data:
            data["proxy_port"] = 8123
            
    if "tor_port" not in data:
        data["tor_port"] = None
            
    if "udp_port" not in data:
        data["udp_port"] = 9000

    # Start the loop
    reactor.listenUDP(
        data["udp_port"],
        Coordinator(
            data["proxy_port"],
            data["tor_port"],
            local_cert,
            certs
            )
    )

    reactor.run()

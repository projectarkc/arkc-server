#! /usr/bin/env python

import logging
import argparse
from Crypto.PublicKey import RSA
from hashlib import sha1
from twisted.internet import reactor
from twisted.web.http import HTTPFactory
from twisted_connect_proxy.server import ConnectProxy
from coordinator import Coordinator


def start_proxy(port):
    factory = HTTPFactory()
    factory.protocol = ConnectProxy
    reactor.listenTCP(port, factory, interface="127.0.0.1")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start ArkC server.")
    parser.add_argument("-v", action="store_true", help="show detailed logs")
    parser.add_argument("-up", "--udp-port", default=9000, type=int,
                        help="port for the udp request listener, 9000 by default")
    parser.add_argument("-pp", "--proxy-port", default=8100, type=int,
                        help="port for the local http proxy server, 8100 by default")
    parser.add_argument("-tp", "--tor-port", default=None, type=int,
                        help="port of Tor (usually 9050), leave it blank to run without Tor")
    parser.add_argument("-rp", "--remote-port", default=8000, type=int,
                        help="port of client's listener, 8000 by default")
    parser.add_argument("-rc", "--remote-cert", type=str, required=True,
                        help="certificate containing public key of the client (REQUIRED)",
                        dest="remote_cert_path")
    parser.add_argument("-lc", "--local-cert", type=str, required=True,
                        help="certificate containing private key of local (REQUIRED)",
                        dest="local_cert_path")
    args = parser.parse_args()

    certs = dict()
    try:
        with open(args.remote_cert_path, "r") as f:
            remote_cert_txt = f.read()
            remote_cert = RSA.importKey(remote_cert_txt)
            certs[sha1(remote_cert_txt).hexdigest()] = remote_cert
    except Exception as err:
        print ("Fatal error while loading client certificate.")
        print (err)
        quit()

    try:
        with open(args.local_cert_path, "r") as f:
            local_cert = RSA.importKey(f.read())
        if not local_cert.has_private():
            print("Fatal error, no private key included in local certificate.")
    except IOError as err:
        print ("Fatal error while loading local certificate.")
        print (err)
        quit()

    if args.v:
        logging.basicConfig(level=logging.INFO)
    start_proxy(args.proxy_port)
    reactor.listenUDP(
        args.udp_port,
        Coordinator(
            args.proxy_port,
            args.tor_port,
            local_cert,
            certs,
            args.remote_port
            )
    )

    reactor.run()

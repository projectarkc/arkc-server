#! /usr/bin/env python

import logging
import argparse
from Crypto.PublicKey import RSA
from twisted.internet import reactor
from twisted.internet.protocol import Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from twisted.internet.protocol import DatagramProtocol
from twisted.web.http import HTTPFactory
from proxy.server import ConnectProxy


class ClientConnector(Protocol):

    def __init__(self, initiator, proxy_port):
        self.initiator = initiator
        self.proxy_connector = ProxyConnector(self)
        point = TCP4ClientEndpoint(reactor, "127.0.0.1", proxy_port)
        connectProtocol(point, self.proxy_connector)

    def connectionMade(self):
        logging.info("connected to " + str(self.transport.getPeer()))
        self.initiator.pending_request -= 1
        if self.initiator.pending_request > 0:
            self.initiator.connectClient()

    def dataReceived(self, data):
        self.proxy_connector.transport.write(data)

    def connectionLost(self, reason):
        logging.info("client connection lost with " + str(reason))


class ProxyConnector(Protocol):

    def __init__(self, initiator):
        self.initiator = initiator

    def connectionMade(self):
        logging.info("connected to " + str(self.transport.getPeer()))

    def dataReceived(self, response):
        logging.info("received %d bytes from " %
                     len(response) + str(self.transport.getPeer()))
        self.initiator.transport.write(response)

    def connectionLost(self, reason):
        logging.info("target connection lost with " + str(reason))
        self.initiator.transport.loseConnection()


class Coodinator(DatagramProtocol):

    def __init__(self, host, ctl_port, client_port, proxy_port):
        self.host = host
        self.ctl_port = ctl_port
        self.client_port = client_port
        self.proxy_port = proxy_port
        self.pending_request = 0

    def startProtocol(self):
        self.transport.connect(self.host, self.ctl_port)
        logging.info("coodinator connected to %s:%d" %
                     (self.host, self.ctl_port))

    def datagramReceived(self, data, addr):
        self.pending_request += len(data)
        self.connectClient()

    def connectClient(self):
        point = TCP4ClientEndpoint(reactor, self.host, self.client_port)
        connectProtocol(point, ClientConnector(self, self.proxy_port))


def start_proxy(port):
    factory = HTTPFactory()
    factory.protocol = ConnectProxy
    reactor.listenTCP(port, factory, interface="127.0.0.1")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start ArkC server.")
    parser.add_argument("-v", action="store_true", help="show detailed logs")
    parser.add_argument("-up", "--udp-port", default=9000, type=int,
                        help="port for the udp request listener, 9000 by default")
    parser.add_argument("-pp", "--proxy-port", default=9050, type=int,
                        help="port for the local http proxy server, 9050 by default")
    parser.add_argument("-rc", "--remote-control-port", default=8002, type=int,
                        help="port of control on the client side, i.e. the udp request listener, \
                            i.e. the port udp listener communicates with, 8002 by default")
    parser.add_argument("-rh", "--remote-host", type=str, required=True,
                        help="host of client (REQUIRED)")
    parser.add_argument("-rp", "--remote-port", default=8000, type=int,
                        help="port of client's listener, 8000 by default")
    parser.add_argument("-rc", "--remote-cert", type=str, required=True,
                        help="certificate containing public key of the client (REQUIRED)",
                        dest="remote_cert_path")
    parser.add_argument("-lc", "--local-cert", type=str, required=True,
                        help="certificate containing private key of local (REQUIRED)",
                        dest="local_cert_path")
    args = parser.parse_args()

    try:
        with open(args.remote_cert_path, "r") as f:
            remote_cert = RSA.importKey(f.read())
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
    reactor.listenUDP(args.udp_port,
                      Coodinator(args.remote_host, args.remote_control_port, args.remote_port,
                                 args.proxy_port))
    reactor.run()

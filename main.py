#! /usr/bin/env python

import logging
from twisted.internet import reactor
from twisted.internet.protocol import Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from twisted.internet.protocol import DatagramProtocol
from twisted.web.http import HTTPFactory
from proxy import ConnectProxy

PROXY_PORT = 9050


class ClientConnector(Protocol):

    def __init__(self, initiator):
        self.initiator = initiator
        self.proxy_connector = ProxyConnector(self)
        point = TCP4ClientEndpoint(reactor, "127.0.0.1", PROXY_PORT)
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
        # TODO: automatic retry on failure
        logging.info("target connection lost with " + str(reason))
        self.initiator.transport.loseConnection()


class Coodinator(DatagramProtocol):

    def __init__(self, host, ctl_port, client_port):
        self.host = host
        self.ctl_port = ctl_port
        self.client_port = client_port
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
        connectProtocol(point, ClientConnector(self))


def start_proxy():
    factory = HTTPFactory()
    factory.protocol = ConnectProxy
    reactor.listenTCP(PROXY_PORT, factory, interface="127.0.0.1")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    start_proxy()
    reactor.listenUDP(9000, Coodinator("127.0.0.1", 8002, 8000))
    reactor.run()

# TODO: support other protocols

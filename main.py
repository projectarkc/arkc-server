#! /usr/bin/env python3

import logging
from twisted.internet import reactor
from twisted.internet.protocol import Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from twisted.internet.protocol import DatagramProtocol
from utils import http_proxy_request_parser


class ClientConnector(Protocol):

    def __init__(self, initiator):
        self.initiator = initiator

    def connectionMade(self):
        logging.info("connected to " + str(self.transport.getPeer()))
        self.initiator.pending_request -= 1
        if self.initiator.pending_request > 0:
            self.initiator.connectClient()

    def dataReceived(self, raw_request):
        host, port, request = http_proxy_request_parser(
            raw_request.decode("UTF-8"))
        point = TCP4ClientEndpoint(reactor, host, port)
        connectProtocol(point, TargetConnector(request, self))

    def connectionLost(self, reason):
        logging.info("client connection lost with " + str(reason))


class TargetConnector(Protocol):

    def __init__(self, request, initiator):
        self.request = request
        self.initiator = initiator

    def connectionMade(self):
        logging.info("connected to " + str(self.transport.getPeer()))
        self.transport.write(bytes(self.request, "UTF-8"))

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

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    reactor.listenUDP(9000, Coodinator("127.0.0.1", 8002, 8000))
    reactor.run()

# TODO: support other protocols

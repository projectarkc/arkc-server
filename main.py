#! /usr/bin/env python3

import logging
from twisted.internet import reactor
from twisted.internet.protocol import Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from utils import http_proxy_request_parser


class ClientConnector(Protocol):

    def connectionMade(self):
        logging.info("connected to " + str(self.transport.getPeer()))

    def dataReceived(self, raw_request):
        host, port, request = http_proxy_request_parser(
            raw_request.decode("UTF-8"))
        point = TCP4ClientEndpoint(reactor, host, port)
        connectProtocol(point, TargetConnector(request, self))


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

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    point = TCP4ClientEndpoint(reactor, "127.0.0.1", 8000)
    connectProtocol(point, ClientConnector())
    reactor.run()
    
# TODO: support other protocols

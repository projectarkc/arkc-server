import logging
from twisted.internet import reactor
from twisted.internet.protocol import Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from proxy import ProxyConnector
from auth import generate_auth_msg


class ClientConnector(Protocol):

    def __init__(self, initiator, salt, string, pri, client_pub, proxy_port):
        self.initiator = initiator
        self.salt = salt
        self.string = string
        self.pri = pri
        self.client_pub = client_pub
        self.proxy_connector = ProxyConnector(self)
        point = TCP4ClientEndpoint(reactor, "127.0.0.1", proxy_port)
        connectProtocol(point, self.proxy_connector)

    def connectionMade(self):
        logging.info("connected to " + str(self.transport.getPeer()))
        # TODO: store keys and string in factory
        self.transport.write(
            generate_auth_msg(self.salt, self.string, self.pri, self.client_pub))
        self.initiator.pending_request -= 1
        if self.initiator.pending_request > 0:
            self.initiator.connect_client()

    def dataReceived(self, data):
        # TODO: decrypt data
        self.proxy_connector.transport.write(data)

    def connectionLost(self, reason):
        logging.info("client connection lost with " + str(reason))

import logging
from twisted.internet import reactor
from twisted.internet.protocol import Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from proxy import ProxyConnector


class ClientConnector(Protocol):

    def __init__(self, initiator, salt):
        self.initiator = initiator
        self.salt = salt
        self.string = self.initiator.string
        self.pri = self.initiator.initiator.pri
        self.client_pub = self.initiator.client_pub
        self.proxy_port = self.initiator.initiator.proxy_port
        self.proxy_connector = ProxyConnector(self)
        point = TCP4ClientEndpoint(reactor, "127.0.0.1", self.proxy_port)
        connectProtocol(point, self.proxy_connector)

    def generate_auth_msg(self):
        """Generate encrypted message.

        The message is in the form
            server_pri(salt + local_pub(string))
        """
        encrypted_string = self.client_pub.encrypt(self.string, "r")
        return self.pri.encrypt(self.salt + encrypted_string, "r")

    def connectionMade(self):
        logging.info("connected to " + str(self.transport.getPeer()))
        self.transport.write(self.generate_auth_msg())

    def dataReceived(self, data):
        # TODO: decrypt data
        self.proxy_connector.transport.write(data)

    def connectionLost(self, reason):
        logging.info("client connection lost with " + str(reason))


class ClientConnectorCreator:

    def __init__(self, initiator, client_pub, host, port, string):
        self.initiator = initiator
        self.client_pub = client_pub
        self.host = host
        self.port = port
        self.string = string

    def connect(self, salt):
        connector = ClientConnector(self, salt)
        point = TCP4ClientEndpoint(reactor, self.host, self.port)
        connectProtocol(point, connector)
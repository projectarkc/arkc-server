import logging
from twisted.internet import reactor
from twisted.internet.protocol import Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from proxy import ProxyConnector
from Crypto.Cipher import AES


class ClientConnector(Protocol):

    def __init__(self, initiator, salt):
        self.initiator = initiator
        self.salt = salt
        self.string = self.initiator.string
        self.cipher = self.initiator.cipher
        self.pri = self.initiator.initiator.pri
        self.client_pub = self.initiator.client_pub
        self.buffer =""
        self.segment_size = 4096
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
        self.buffer += data
        while len(self.buffer) > self.segment_size:
            self.write()

    def write(self):
        if len(self.buffer) < self.segment_size:
            write_buffer = self.cipher.decrypt(self.buffer)
        else:
            write_buffer = self.cipher.decrypt(self.buffer[:self.segment_size])
            self.buffer = self.buffer[self.segment_size:]
        self.transport.write(write_buffer)

    def connectionLost(self, reason):
        logging.info("client connection lost with " + str(reason))


class ClientConnectorCreator:

    def __init__(self, initiator, client_pub, host, port, string):
        self.initiator = initiator
        self.client_pub = client_pub
        self.host = host
        self.port = port
        self.string = string
        self.cipher = AES.new(self.string, AES.MODE_CFB, self.string)

    def connect(self, salt):
        connector = ClientConnector(self, salt)
        point = TCP4ClientEndpoint(reactor, self.host, self.port)
        connectProtocol(point, connector)
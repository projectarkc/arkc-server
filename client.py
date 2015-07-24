import logging
from random import choice
from string import letters as L
from string import digits as D
from collections import deque
from twisted.internet import reactor
from twisted.internet.protocol import Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from txsocksx.client import SOCKS4ClientEndpoint
from proxy import ProxyConnector
from Crypto.Cipher import AES


class ClientConnector(Protocol):

    def __init__(self, initiator):
        self.initiator = initiator
        self.split_char = chr(30) * 5
        self.pw_gen = lambda l: ''.join([choice(L + D) for i in range(l)])
        self.main_pw = self.initiator.main_pw
        self.pri = self.initiator.initiator.pri
        self.client_pub = self.initiator.client_pub
        self.session_pw = self.pw_gen(16)
        self.cipher = AES.new(self.session_pw, AES.MODE_CFB, self.main_pw)
        self.buffer = ""
        self.write_queue = deque()
        self.proxy_port = self.initiator.initiator.proxy_port
        self.proxy_connector = ProxyConnector(self)
        point = TCP4ClientEndpoint(reactor, "127.0.0.1", self.proxy_port)
        connectProtocol(point, self.proxy_connector)

    def generate_auth_msg(self):
        """Generate encrypted message.

        The message is in the form
            server_sign(main_pw) (HEX) +
            client_pub(session_pw)
        Total length is 512 + 256 = 768 bytes
        """
        hex_sign = '%X' % self.pri.sign(self.main_pw, None)[0]
        pw_enc = self.client_pub.encrypt(self.session_pw, None)[0]
        return hex_sign + pw_enc

    def connectionMade(self):
        logging.info("connected to " + str(self.transport.getPeer()))
        self.transport.write(self.generate_auth_msg())

    def dataReceived(self, data):
        self.buffer += data
        recv = self.buffer.split(self.split_char)
        self.write_queue.extend(recv[:-1])
        self.buffer = recv[-1]  # incomplete message
        while self.write_queue:
            self.write()

    def write(self):
        write_buffer = self.cipher.decrypt(self.write_queue.popleft())
        self.proxy_connector.transport.write(write_buffer)

    def connectionLost(self, reason):
        logging.info("client connection lost with " + str(reason))
        while self.write_queue:
            self.write()


class ClientConnectorCreator:

    def __init__(self, initiator, client_pub, host, port, main_pw):
        self.initiator = initiator
        self.tor_port = self.initiator.tor_port
        self.client_pub = client_pub
        self.host = host
        self.port = port
        self.main_pw = main_pw

    def connect(self):
        connector = ClientConnector(self)
        if self.tor_port:
            tor_point = TCP4ClientEndpoint(reactor, "127.0.0.1", self.tor_port)
            point = SOCKS4ClientEndpoint(self.host, self.port, tor_point)
        else:
            point = TCP4ClientEndpoint(reactor, self.host, self.port)
        connectProtocol(point, connector)

import logging
from utils import addr_to_str
from random import choice
from string import letters as L
from string import digits as D
from collections import deque
from twisted.internet import reactor
from twisted.internet.protocol import Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from txsocksx.client import SOCKS5ClientEndpoint
from proxy import ProxyConnector
from Crypto.Cipher import AES


class ClientConnector(Protocol):

    def __init__(self, initiator):
        self.initiator = initiator
        self.split_char = chr(30) * 5
        self.close_char = chr(4) * 5
        self.pw_gen = lambda l: ''.join([choice(L + D) for i in range(l)])
        self.main_pw = self.initiator.main_pw
        self.pri = self.initiator.initiator.pri
        self.client_pub = self.initiator.client_pub
        self.session_pw = self.pw_gen(16)
        self.cipher = AES.new(self.session_pw, AES.MODE_CFB, self.main_pw)
        self.buffer = ""
        self.write_queues = dict()  # stores decrypted data
        self.proxy_port = self.initiator.initiator.proxy_port
        self.proxy_connectors = dict()
        host, port = "127.0.0.1", self.proxy_port
        self.proxy_point = TCP4ClientEndpoint(reactor, host, port)

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

    def new_proxy_conn(self, conn_id):
        """Return a Deferred object of the proxy connector."""
        logging.info("adding connection id " + conn_id)
        try:
            assert conn_id not in self.write_queues
            self.write_queues[conn_id] = deque()
            self.proxy_connectors[conn_id] = ProxyConnector(self, conn_id)
            point, connector = self.proxy_point, self.proxy_connectors[conn_id]
            d = connectProtocol(point, connector)
            d.addErrback(lambda ignored: logging.error("cannot connect proxy"))
            return d
        except AssertionError:
            logging.error("duplicate id")

    def del_proxy_conn(self, conn_id):
        logging.info("deleting connection id " + conn_id)
        try:
            assert self.write_queues.pop(conn_id, None) is not None
            assert self.proxy_connectors.pop(conn_id, None)
        except AssertionError:
            logging.warning("deleting non-existing key")

    def connectionMade(self):
        logging.info("connected to client " +
                     addr_to_str(self.transport.getPeer()))
        self.transport.write(self.generate_auth_msg())
        self.initiator.number += 1

    def dataReceived(self, recv_data):
        logging.info("received %d bytes from client " % len(recv_data) +
                     addr_to_str(self.transport.getPeer()))
        self.buffer += recv_data
        recv = self.buffer.split(self.split_char)
        touched_ids = set()
        for text_enc in recv[:-1]:
            text_dec = self.cipher.decrypt(text_enc)
            conn_id, data = text_dec[:2], text_dec[2:]
            if data == self.close_char:
                if conn_id in self.proxy_connectors:
                    self.proxy_connectors[conn_id].transport.loseConnection()
                else:
                    logging.warning("closing non-existing connection")
            else:
                if conn_id not in self.write_queues:
                    deferred = self.new_proxy_conn(conn_id)
                    deferred.addCallback(lambda ignored: self.write(conn_id))
                else:
                    touched_ids.add(conn_id)
                self.write_queues[conn_id].append(data)
        self.buffer = recv[-1]  # incomplete message
        for conn_id in touched_ids:
            self.write(conn_id)

    def write(self, conn_id):
        """Flush the queue of conn_id."""
        while self.write_queues[conn_id]:
            data = self.write_queues[conn_id].popleft()
            if data:
                logging.info("sending %d bytes to proxy %s from id %s" % (
                                len(data),
                                addr_to_str(self.proxy_connectors[conn_id]
                                            .transport.getPeer()),
                                conn_id))
                self.proxy_connectors[conn_id].transport.write(data)

    def finish(self, conn_id):
        self.write_client(self.close_char, conn_id)
        self.del_proxy_conn(conn_id)

    def clean(self):
        for conn_id in self.write_queues.keys():
            self.write(conn_id)

    def write_client(self, data, conn_id):
        to_write = self.cipher.encrypt(conn_id + data) + self.split_char
        logging.info("sending %d bytes to client %s with id %s" % (len(data),
                     addr_to_str(self.transport.getPeer()),
                     conn_id))
        self.transport.write(to_write)

    def connectionLost(self, reason):
        logging.info("client connection lost: " +
                     addr_to_str(self.transport.getPeer()))
        self.initiator.number -= 1
        self.clean()


class ClientConnectorCreator:

    def __init__(self, initiator, client_pub, host, port, main_pw):
        self.initiator = initiator
        self.tor_point = self.initiator.tor_point
        self.client_pub = client_pub
        self.host = host
        self.port = port
        self.main_pw = main_pw
        self.number = 0

    def connect(self):
        connector = ClientConnector(self)
        if self.tor_point:
            point = SOCKS5ClientEndpoint(self.host, self.port, self.tor_point)
        else:
            point = TCP4ClientEndpoint(reactor, self.host, self.port)
        connectProtocol(point, connector)

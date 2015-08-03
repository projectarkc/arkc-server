import logging
from utils import addr_to_str
from random import choice
from string import letters as L
from string import digits as D
from collections import deque
from twisted.internet import reactor
from twisted.internet.protocol import Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from txsocksx.client import SOCKS5ClientEndpoint as SOCKS5Point
from proxy import ProxyConnector
from utils import AESCipher


class ClientConnector(Protocol):

    def __init__(self, initiator):
        self.initiator = initiator
        self.split_char = chr(27) + chr(28) + chr(29) + chr(30) + chr(31)
        self.close_char = chr(4) * 5
        self.pw_gen = lambda l: ''.join([choice(L + D) for i in range(l)])
        self.main_pw = self.initiator.main_pw
        self.pri = self.initiator.initiator.pri
        self.client_pub = self.initiator.client_pub
        self.session_pw = self.pw_gen(16)
        self.cipher = AESCipher(self.session_pw, self.main_pw)
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

    def proxy_lost(self, conn_id):
        """Deal with the situation when proxy connection is lost unexpectedly.

        Need to switch to a more elegant solution.
        """
        # TODO: switch to a more elegant solution
        conn = self.proxy_connectors[conn_id]
        logging.error("proxy connection %s lost unexpectedly" % conn_id)
        conn.write()
        self.finish(conn_id)

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
                    conn = self.proxy_connectors[conn_id]
                    if not conn.transport:
                        self.proxy_lost(conn_id)
                    else:
                        conn.transport.loseConnection()
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
                conn = self.proxy_connectors[conn_id]
                if not conn.transport:
                    self.proxy_lost(conn_id)
                else:
                    logging.info("sending %d bytes to proxy %s from id %s" % (
                                    len(data),
                                    addr_to_str(conn.transport.getPeer()),
                                    conn_id))
                    conn.transport.write(data)

    def finish(self, conn_id):
        self.write_client(self.close_char, conn_id)
        self.del_proxy_conn(conn_id)

    def clean(self):
        for conn_id in self.write_queues.keys():
            self.write(conn_id)
            conn = self.proxy_connectors[conn_id]
            if not conn.transport:
                self.proxy_lost(conn_id)
            else:
                conn.transport.loseConnection()

    def write_client(self, data, conn_id):
        to_write = self.cipher.encrypt(conn_id + data) + self.split_char
        logging.info("sending %d bytes to client %s with id %s" % (len(data),
                     addr_to_str(self.transport.getPeer()),
                     conn_id))
        self.transport.write(to_write)

    def connectionLost(self, reason):
        logging.info("client connection lost: " +
                     addr_to_str(self.transport.getPeer()))
        self.clean()
        self.initiator.retry()


class ClientConnectorCreator:

    def __init__(self, initiator, client_pub, host, port, main_pw, req_num):
        self.initiator = initiator
        self.tor_point = self.initiator.tor_point
        self.client_pub = client_pub
        self.host = host
        self.port = port
        self.main_pw = main_pw
        self.req_num = req_num
        self.number = 0
        self.max_retry = 5
        self.retry_count = 0

    def retry(self):
        self.number -= 1
        if self.retry_count < self.max_retry:
            host, port = self.host, self.port
            logging.warning("retry connection to %s:%d" % (host, port))
            self.retry_count += 1
            self.connect()

    def success(self):
        self.retry_count = 0
        self.connect()

    def connect(self):
        if self.number < self.req_num:
            self.number += 1
            connector = ClientConnector(self)
            if self.tor_point:
                point = SOCKS5Point(self.host, self.port, self.tor_point)
            else:
                point = TCP4ClientEndpoint(reactor, self.host, self.port)
            deferred = connectProtocol(point, connector)
            deferred.addCallback(lambda ignored: self.success())
            deferred.addErrback(lambda ignored: self.retry())

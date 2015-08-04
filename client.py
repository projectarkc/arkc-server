import logging
from utils import addr_to_str
from random import choice, randrange
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
    """Handle one connection to a client.

    Its functions include:
        - Initiate connection to client.
        - Send an authentication message to client to start transmission.
        - Receive encrypted data packets from client, separated by split_char.
        - Decrypt data packets. Get the ID (first 2 bytes of decrypted text).
          Create a connection to HTTP proxy for each unique ID.
        - Forward request to HTTP proxy. Encrypt and send back the response.
        - Close connection to HTTP proxy for a given ID if a packet
          of the ID with close_char is received.
    """

    def __init__(self, initiator):
        self.initiator = initiator

        # control characters
        self.split_char = chr(27) + chr(28) + chr(29) + chr(30) + chr(31)
        self.close_char = chr(4) * 5

        # generate random string of the given length
        self.pw_gen = lambda l: ''.join([choice(L + D) for i in range(l)])

        self.main_pw = self.initiator.main_pw
        self.pri = self.initiator.initiator.pri
        self.client_pub = self.initiator.client_pub
        self.session_pw = self.pw_gen(16)

        self.cipher = AESCipher(self.session_pw, self.main_pw)

        self.buffer = ""

        # maps ID to decrypted data segments
        self.write_queues = dict()
        self.proxy_port = self.initiator.initiator.proxy_port
        self.proxy_connectors = dict()

        # Create an endpoint for the HTTP proxy
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
        """Create a connection to HTTP proxy corresponding to the given ID.

        Return a Deferred object of the proxy connector.
        """
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
        """Remove the given ID.

        Triggered when the ID is no longer in use.
        """
        logging.info("deleting connection id " + conn_id)
        try:
            assert self.write_queues.pop(conn_id, None) is not None
            assert self.proxy_connectors.pop(conn_id, None)
        except AssertionError:
            logging.warning("deleting non-existing key %s" % conn_id)

    def connectionMade(self):
        """Event handler of being successfully connected to the client."""
        logging.info("connected to client " +
                     addr_to_str(self.transport.getPeer()))
        self.transport.write(self.generate_auth_msg())

        # Reset the connection after a random time
        expire_time = randrange(30, 90)
        reactor.callLater(expire_time, self.client_reset)

    def dataReceived(self, recv_data):
        """Event handler of receiving some data from client.

        Split, decrypt, and forward them using corresponding proxy connections.
        """
        logging.info("received %d bytes from client " % len(recv_data) +
                     addr_to_str(self.transport.getPeer()))
        self.buffer += recv_data

        # a list of encrypted data packages
        # the last item may be incomplete
        recv = self.buffer.split(self.split_char)

        # keep track of which existing IDs have new data to forward
        touched_ids = set()

        # leave the last (may be incomplete) item intact
        for text_enc in recv[:-1]:
            text_dec = self.cipher.decrypt(text_enc)
            conn_id, data = text_dec[:2], text_dec[2:]

            if data == self.close_char:
                # close connection and remove the ID
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
                    # create new connection to HTTP proxy
                    deferred = self.new_proxy_conn(conn_id)
                    # forward data after the connection is created
                    deferred.addCallback(lambda ign: self.proxy_write(conn_id))
                else:
                    # mark the ID as touched
                    touched_ids.add(conn_id)
                self.write_queues[conn_id].append(data)

        self.buffer = recv[-1]  # incomplete message

        # trigger forward action for the IDs with new data
        for conn_id in touched_ids:
            self.proxy_write(conn_id)

    def connectionLost(self, reason):
        """Event handler of losing the connection to the client.

        Will retry connecting if the max retry count is not reached.
        """
        logging.info("client connection lost: " +
                     addr_to_str(self.transport.getPeer()))
        self.client_clean()
        self.initiator.retry()

    def proxy_write(self, conn_id):
        """Forward all the data pending for the ID to the HTTP proxy."""
        while conn_id in self.write_queues and self.write_queues[conn_id]:
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

    def proxy_lost(self, conn_id):
        """Deal with the situation when proxy connection is lost unexpectedly.

        That is when conn.transport becomes None.
        """
        # TODO: why does this happen?
        conn = self.proxy_connectors[conn_id]
        conn.dead = True
        logging.warning("proxy connection %s lost unexpectedly" % conn_id)
        conn.write()
        self.proxy_finish(conn_id)

    def proxy_finish(self, conn_id):
        """Write all pending response data to client and remove ID.

        Called when proxy connection is lost.
        """
        self.client_write(self.close_char, conn_id)
        self.del_proxy_conn(conn_id)

    def client_write(self, data, conn_id):
        """Encrypt and write data the client.

        Encrypted packets should be separated by split_char.
        The first 2 bytes of a raw packet should be its ID.
        """
        to_write = self.cipher.encrypt(conn_id + data) + self.split_char
        logging.info("sending %d bytes to client %s with id %s" % (len(data),
                     addr_to_str(self.transport.getPeer()),
                     conn_id))
        self.transport.write(to_write)

    def client_reset(self):
        """Called after a random time to reset a existing connection to client.

        May result in better performance.
        """
        self.loseConnection()
        # TODO: existing IDs should be re-allocated

    def client_clean(self):
        """Close all connections to proxy.

        Called when client connection is lost.
        """
        for conn_id in self.write_queues.keys():
            self.proxy_write(conn_id)
            conn = self.proxy_connectors[conn_id]
            if not conn.transport:
                self.proxy_lost(conn_id)
            else:
                conn.transport.loseConnection()


class ClientConnectorCreator:
    """Creator of all ClientConnectors to one client.

    The ClientConnectorCreator instance will be passed to all ClientConnectors
    spawned from it as "initiator" parameter.
    """

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
        """Triggered when a failure connecting client occurs.

        Decrement the number of available connections
        (which is pre-added when trying to connect),
        and retry until the max retry count is reached.
        """
        self.number -= 1
        if self.retry_count < self.max_retry:
            host, port = self.host, self.port
            logging.warning("retry connection to %s:%d" % (host, port))
            self.retry_count += 1
            self.connect()

    def success(self):
        """Triggered when successfully connected to client.

        Reset retry count and continue adding connections until the required
        available connection number (specified by client through UDP message)
        is reached.
        """
        self.retry_count = 0
        self.connect()

    def connect(self):
        if self.number < self.req_num:

            # pre-add the available connection count
            # will be decremented if failure occurs
            self.number += 1

            connector = ClientConnector(self)

            # connect through Tor if required, direct connection otherwise
            if self.tor_point:
                point = SOCKS5Point(self.host, self.port, self.tor_point)
            else:
                point = TCP4ClientEndpoint(reactor, self.host, self.port)

            deferred = connectProtocol(point, connector)
            # trigger success or failure action depending on the result
            deferred.addCallback(lambda ignored: self.success())
            deferred.addErrback(lambda ignored: self.retry())

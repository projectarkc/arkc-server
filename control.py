import logging
from collections import deque
from random import expovariate, choice
from utils import addr_to_str
from client import ClientConnector
from proxy import ProxyConnector
from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from txsocksx.client import SOCKS5ClientEndpoint as SOCKS5Point
import time

class Control:
    """The core part of the server, acting as a bridge between client and proxy.

    One Control instance corresponds to one client (with unique SHA1).

    Its functions include:
        - Maintain a certain number of connections to client
            through ClientConnectors, as specified in UDP message.
        - Reset and re-connect at a random period (between 30 to 90 secs),
            for better performance.
        - Stash request data from client. Create ProxyConnectors on demand,
            through which to send the data.
        - Stash reponse data from proxy. Pick a connection to client to
            send them back.

    The Control itself is passed to both ClientConnectors and ProxyConnectors
        spawned from it as the `initiator` parameter.
    """

    def __init__(self, initiator, client_pub, host, port, main_pw, req_num):
        self.initiator = initiator
        self.close_char = chr(4) * 5
        self.tor_point = self.initiator.tor_point
        self.client_pub = client_pub
        self.host = host
        self.port = port
        self.main_pw = main_pw
        self.req_num = req_num
        self.number = 0
        self.max_retry = 5
        self.retry_count = 0
        self.client_connectors = []

        # maps ID to decrypted data segments
        self.write_queues = dict()

        # maps ID to ProxyConnectors
        self.proxy_connectors = dict()

        # Create an endpoint for the HTTP proxy
        host, port = "127.0.0.1", self.initiator.proxy_port
        self.proxy_point = TCP4ClientEndpoint(reactor, host, port)

    def connect(self):
        """Connect client."""
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
            deferred.addCallback(self.success)
            deferred.addErrback(lambda ignored: self.retry())

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

    def success(self, conn):
        """Triggered when successfully connected to client.

        Reset retry count and continue adding connections until the required
        available connection number (specified by client through UDP message)
        is reached.
        """
        self.retry_count = 0
        self.client_connectors.append(conn)

        # Reset the connection after a random time
        expire_time = expovariate(1.0 / 60)
        reactor.callLater(expire_time, self.client_reset, conn)

        self.connect()

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
            d.addCallback(lambda ignored: self.proxy_write(conn_id))
            d.addErrback(lambda ignored: logging.error("cannot connect proxy"))
        except AssertionError:
            logging.error("duplicate id")

    def del_proxy_conn(self, conn_id):
        """Remove the given ID.

        Triggered when the ID is no longer in use.
        """
        logging.info("deleting connection id " + conn_id)
        try:
            assert self.write_queues.pop(conn_id, None) is not None
            assert self.proxy_connectors.pop(conn_id, None) is not None
        except AssertionError:
            logging.warning("deleting non-existing key %s" % conn_id)

    def client_recv(self, recv):
        """Handle request from client.

        Should be decrypted by ClientConnector first.
        """
        conn_id, data = recv[:2], recv[2:]

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
            if conn_id not in self.proxy_connectors:
                self.new_proxy_conn(conn_id)
                self.write_queues[conn_id].append(data)
            else:
                self.write_queues[conn_id].append(data)
                self.proxy_write(conn_id)

    def client_write(self, data, conn_id):
        """Pick a client connector and write the data.

        Triggered by proxy_recv or proxy_finish.
        """
        # TODO: use an algorithm to pick the optimal connector
        # TODO: use an error return value when self.client_connectors = []
        
        i = 0
        while i <= 5 and len(self.client_connectors) == 0:
            time.sleep(0.02)
        if len(self.client_connectors) > 0:
            conn = choice(self.client_connectors)
            conn.write(data, conn_id)
        else:
            logging.error("no client_connectiors available, %i dumped." % len(data))

    def client_reset(self, conn):
        """Called after a random time to reset a existing connection to client.

        May result in better performance.
        """
        conn.transport.loseConnection()

    def client_lost(self, conn):
        """Triggered by a ClientConnector's connectionLost method.

        Remove the closed connection and retry creating it.
        """
        self.client_connectors.remove(conn)
        self.number -= 1
        self.connect()

    def proxy_write(self, conn_id):
        """Forward all the data pending for the ID to the HTTP proxy."""
        while conn_id in self.write_queues and self.write_queues[conn_id]:
            data = self.write_queues[conn_id].popleft()
            if data is not None:
                conn = self.proxy_connectors[conn_id]
                if not conn.transport:
                    self.proxy_lost(conn_id)
                else:
                    logging.info("sending %d bytes to proxy %s from id %s" % (
                                    len(data),
                                    addr_to_str(conn.transport.getPeer()),
                                    conn_id))
                    conn.transport.write(data)

    def proxy_recv(self, data, conn_id):
        """Call client_write on receiving data from proxy."""
        self.client_write(data, conn_id)

    def proxy_lost(self, conn_id):
        """Deal with the situation when proxy connection is lost unexpectedly.

        That is when conn.transport becomes None.
        """
        # TODO: why does this happen?
        conn = self.proxy_connectors[conn_id]
        conn.dead = True
        logging.warning("proxy connection %s lost unexpectedly" % conn_id)
        conn.respond()
        self.proxy_finish(conn_id)

    def proxy_finish(self, conn_id):
        """Write all pending response data to client and remove ID.

        Called when proxy connection is lost.
        """
        self.client_write(self.close_char, conn_id)
        self.del_proxy_conn(conn_id)

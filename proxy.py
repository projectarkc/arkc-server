import logging
from collections import deque
from twisted.internet.protocol import Protocol

from utils import addr_to_str


class ProxyConnector(Protocol):
    """Handle a single connection to the HTTP proxy.
    Initiated by a ClientConnector (passed as self.initiator).
    One ProxyConnector corresponds to a unique ID.
    """

    def __init__(self, initiator, conn_id):
        self.initiator = initiator
        self.conn_id = conn_id
        self.buffer = ''
        self.write_queue = deque()

        # 4096(total) - 1(type) - 2(id) - 3(index) - 7(splitchar)
        self.segment_size = 4096

        # set as True when self.transport becomes None,
        # but self.connectionLost() is not triggered
        self.dead = False

    def connectionMade(self):
        """Event handler of being successfully connected to HTTP proxy."""
        logging.info("connected to proxy %s with id %s" %
                     (addr_to_str(self.transport.getPeer()), self.conn_id))

    def dataReceived(self, response):
        """Event handler of receiving data from HTTP proxy.
        Will cut them into segments and call self.respond() to write them.
        """
        logging.debug("received %d bytes from proxy with id %s" %
                      (len(response), self.conn_id))
        self.buffer += response
        while self.buffer:
            self.write_queue.append(self.buffer[:self.segment_size])
            self.buffer = self.buffer[self.segment_size:]
        self.respond()

    def connectionLost(self, reason):
        """Event handler of losing proxy connection.
        Exclude the situation when self.transport has already become None
        but this event has not been triggered.
        """
        if not self.dead:
            logging.info("proxy connection %s lost" % self.conn_id)
            self.respond()
            self.initiator.proxy_finish(self.conn_id)

    def respond(self):
        """Send all data to Control.
        Pass the segments one by one to Control's proxy_recv method.
        """
        while self.write_queue:  # TODO: YIELD
            write_buffer = self.write_queue.popleft()
            self.initiator.proxy_recv(write_buffer, self.conn_id)

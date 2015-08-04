import logging
from utils import addr_to_str
from collections import deque
from twisted.internet.protocol import Protocol


class ProxyConnector(Protocol):
    """Handle a single connection to the HTTP proxy.

    Initiated by a ClientConnector (passed as self.initiator).
    One ProxyConnector corresponds to a unique ID.
    """

    def __init__(self, initiator, conn_id):
        self.initiator = initiator
        self.conn_id = conn_id
        self.split_char = chr(27) + chr(28) + chr(29) + chr(30) + chr(31)
        self.buffer = ''
        self.write_queue = deque()
        self.segment_size = 4094    # 4096(total)-2(id)

        # set as True when self.transport becomes None,
        # but self.connectionLost() is not triggered
        self.dead = False

    def connectionMade(self):
        """Event handler of being successfully connected to HTTP proxy."""
        logging.info("connected to proxy %s with id %s" %
                     (addr_to_str(self.transport.getPeer()), self.conn_id))

    def dataReceived(self, response):
        """Event handler of receiving data from HTTP proxy.

        Will cut them into segments and call self.write() to write them.
        """
        logging.info("received %d bytes from proxy with id %s" %
                     (len(response), self.conn_id))
        self.buffer += response
        while len(self.buffer) >= self.segment_size:
            self.write_queue.append(self.buffer[:self.segment_size])
            self.buffer = self.buffer[self.segment_size:]
        if self.buffer:
            self.write_queue.append(self.buffer)
            self.buffer = ""
        self.write()

    def connectionLost(self, reason):
        """Event handler of losing proxy connection.

        Exclude the situation when self.transport has already become None
        but this event has not been triggered.
        """
        if not self.dead:
            logging.info("proxy connection %s lost" % self.conn_id)
            self.write()
            self.initiator.proxy_finish(self.conn_id)

    def write(self):
        """Write all data to client.

        Pass the segments one by one to ClientConnector's client writer
        for ID tagging and encryption.
        """
        while self.write_queue:
            write_buffer = self.write_queue.popleft()
            self.initiator.client_write(write_buffer, self.conn_id)

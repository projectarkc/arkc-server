import logging
from utils import addr_to_str
from collections import deque
from twisted.internet.protocol import Protocol


class ProxyConnector(Protocol):

    def __init__(self, initiator, conn_id):
        self.initiator = initiator
        self.conn_id = conn_id
        self.split_char = chr(27) + chr(28) + chr(29) + chr(30) + chr(31)
        self.buffer = ''
        self.write_queue = deque()
        self.segment_size = 4094    # 4096(total)-2(id)
        self.dead = False

    def connectionMade(self):
        logging.info("connected to proxy %s with id %s" %
                     (addr_to_str(self.transport.getPeer()), self.conn_id))

    def dataReceived(self, response):
        logging.info("received %d bytes with id %s" %
                     (len(response), self.conn_id))
        self.buffer += response
        while len(self.buffer) >= self.segment_size:
            self.write_queue.append(self.buffer[:self.segment_size])
            self.buffer = self.buffer[self.segment_size:]
        if self.buffer:
            self.write_queue.append(self.buffer)
            self.buffer = ""
        self.write()

    def write(self):
        """Flush all data."""
        while self.write_queue:
            write_buffer = self.write_queue.popleft()
            self.initiator.write_client(write_buffer, self.conn_id)

    def connectionLost(self, reason):
        if not self.dead:
            logging.info("proxy connection %s lost" % self.conn_id)
            self.write()
            self.initiator.finish(self.conn_id)

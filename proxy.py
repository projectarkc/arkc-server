import logging
from utils import addr_to_str
from twisted.internet.error import ConnectionDone, ConnectionLost
from collections import deque
from twisted.internet.protocol import Protocol


class ProxyConnector(Protocol):

    def __init__(self, initiator, conn_id):
        self.initiator = initiator
        self.conn_id = conn_id
        self.split_char = chr(30) * 5
        self.buffer = ''
        self.write_queue = deque()
        self.segment_size = 4094    # 4096(total)-2(id)

    def connectionMade(self):
        logging.info("connected to proxy " +
                     addr_to_str(self.transport.getPeer()))

    def dataReceived(self, response):
        logging.info("received %d bytes from proxy " %
                     len(response) + addr_to_str(self.transport.getPeer()))
        self.buffer += response
        while len(self.buffer) >= self.segment_size:
            self.write_queue.append(self.buffer[:self.segment_size])
            self.buffer = self.buffer[self.segment_size:]
        if self.buffer:
            self.write_queue.append(self.buffer)
            self.buffer = ""
        while self.write_queue:
            self.write()

    def write(self):
        write_buffer = self.write_queue.popleft()
        self.initiator.write_client(write_buffer, self.conn_id)

    def connectionLost(self, reason):
        if reason == ConnectionDone:
            logging.info("proxy connection done: " +
                         addr_to_str(self.transport.getPeer()))
        elif reason == ConnectionLost:
            logging.warning("proxy connection lost: " +
                            addr_to_str(self.transport.getPeer()))
        while self.write_queue:
            self.write()
        self.initiator.finish(self.conn_id)

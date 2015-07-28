import logging
from collections import deque
from twisted.internet.protocol import Protocol


class ProxyConnector(Protocol):

    def __init__(self, initiator):
        self.initiator = initiator
        self.split_char = chr(30) * 5
        self.buffer = ''
        self.write_queue = deque()
        self.segment_size = 4096

    def connectionMade(self):
        logging.info("connected to " + str(self.transport.getPeer()))

    def dataReceived(self, response):
        logging.info("received %d bytes from " %
                     len(response) + str(self.transport.getPeer()))
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
        self.initiator.write_client(write_buffer)

    def connectionLost(self, reason):
        logging.info("target connection lost with " + str(reason))
        while self.write_queue:
            self.write()
        self.initiator.transport.loseConnection()

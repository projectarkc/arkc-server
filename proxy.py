import logging
from collections import deque
from twisted.internet.protocol import Protocol


class ProxyConnector(Protocol):

    def __init__(self, initiator):
        self.initiator = initiator
        self.split_char = chr(30) * 5
        self.cipher = self.initiator.cipher
        self.buffer = ''
        self.write_queue = deque()
        self.segment_size = 4096

    def connectionMade(self):
        logging.info("connected to " + str(self.transport.getPeer()))

    def dataReceived(self, response):
        logging.info("received %d bytes from " %
                     len(response) + str(self.transport.getPeer()))
        # self.write_queue.append(response)
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
        to_write = self.cipher.encrypt(write_buffer) + self.split_char
        self.initiator.transport.write(to_write)

    def connectionLost(self, reason):
        logging.info("target connection lost with " + str(reason))
        while self.write_queue:
            self.write()
        self.initiator.transport.loseConnection()

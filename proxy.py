import logging
from twisted.internet.protocol import Protocol


class ProxyConnector(Protocol):

    def __init__(self, initiator):
        self.initiator = initiator
        self.buffer = ''
        self.segment_size = 4096

    def connectionMade(self):
        logging.info("connected to " + str(self.transport.getPeer()))

    def dataReceived(self, response):
        logging.info("received %d bytes from " %
                     len(response) + str(self.transport.getPeer()))
        while len(self.buffer) > self.segment_size:
            self.write()

    def write(self):
        if len(self.buffer) <= self.segment_size:
            write_buffer = self.buffer
        else:
            write_buffer = self.buffer[:self.segment_size]
            self.buffer = self.buffer[self.segment_size:]
        self.initiator.transport.write(self.cipher.encrypt(write_buffer))

    def connectionLost(self, reason):
        logging.info("target connection lost with " + str(reason))
        while self.buffer:
            self.write()
        self.initiator.transport.loseConnection()

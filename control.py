import logging
from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from twisted.internet.protocol import DatagramProtocol
from client import ClientConnector
from auth import decrypt_udp_msg


class Coordinator(DatagramProtocol):

    def __init__(self, host, ctl_port, client_port, proxy_port, pri, client_pub):
        self.host = host
        self.ctl_port = ctl_port
        self.client_port = client_port
        self.proxy_port = proxy_port
        # TODO: store private key in factory
        self.pri = pri
        self.client_pub = client_pub
        self.pending_request = 0

    def startProtocol(self):
        self.transport.connect(self.host, self.ctl_port)
        logging.info("coordinator connected to %s:%d" %
                     (self.host, self.ctl_port))

    def datagramReceived(self, data, addr):
        salt, client_sha1, string = decrypt_udp_msg(data)
        # TODO: check validity
        # TODO: client_sha1 is currently not used
        self.pending_request += 1
        self.connectClient(salt, string)

    def connectClient(self, salt, string):
        point = TCP4ClientEndpoint(reactor, self.host, self.client_port)
        # TODO: string should be unique to each Coordinator instance
        connectProtocol(
            point,
            ClientConnector(
                salt,
                string,
                self.pri,
                self.client_pub,
                self.proxy_port
            )
        )

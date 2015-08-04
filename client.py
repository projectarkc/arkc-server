import logging
from utils import addr_to_str
from os import urandom
from twisted.internet.protocol import Protocol
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

        self.main_pw = self.initiator.main_pw
        self.pri = self.initiator.initiator.pri
        self.client_pub = self.initiator.client_pub
        self.session_pw = urandom(16)

        self.cipher = AESCipher(self.session_pw, self.main_pw)

        self.buffer = ""

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

    def connectionMade(self):
        """Event handler of being successfully connected to the client.

        Reset the connection after a random time (between 30 to 90 secs),
        and tell Control to re-add connection for better performance.
        """
        logging.info("connected to client " +
                     addr_to_str(self.transport.getPeer()))
        self.transport.write(self.generate_auth_msg())

    def dataReceived(self, recv_data):
        """Event handler of receiving some data from client.

        Split, decrypt and hand them back to Control.
        """
        logging.info("received %d bytes from client " % len(recv_data) +
                     addr_to_str(self.transport.getPeer()))
        self.buffer += recv_data

        # a list of encrypted data packages
        # the last item may be incomplete
        recv = self.buffer.split(self.split_char)

        # leave the last (may be incomplete) item intact
        for text_enc in recv[:-1]:
            text_dec = self.cipher.decrypt(text_enc)
            self.initiator.client_recv(text_dec)

        self.buffer = recv[-1]  # incomplete message

    def connectionLost(self, reason):
        """Event handler of losing the connection to the client.

        Call Control to handle it.
        """
        logging.info("client connection lost: " +
                     addr_to_str(self.transport.getPeer()))
        self.initiator.client_lost()

    def write(self, data, conn_id):
        """Encrypt and write data the client.

        Encrypted packets should be separated by split_char.
        The first 2 bytes of a raw packet should be its ID.
        """
        to_write = self.cipher.encrypt(conn_id + data) + self.split_char
        logging.info("sending %d bytes to client %s with id %s" % (len(data),
                     addr_to_str(self.transport.getPeer()),
                     conn_id))
        self.transport.write(to_write)

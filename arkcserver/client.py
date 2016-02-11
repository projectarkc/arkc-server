import logging

from os import urandom
from twisted.internet import reactor
from twisted.internet.protocol import Protocol
from time import time
import struct
import random
from utils import AESCipher
from utils import addr_to_str
from utils import get_timestamp, parse_timestamp


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

        self.main_pw = self.initiator.main_pw
        # control characters
        self.split_char = chr(27) + chr(28) + "%X" % struct.unpack('B', self.main_pw[-2:-1])[
            0] + "%X" % struct.unpack('B', self.main_pw[-3:-2])[0] + chr(31)
        self.pri = self.initiator.initiator.pri
        self.client_pub = self.initiator.client_pub
        self.session_pw = urandom(16)
        self.cipher = AESCipher(self.session_pw, self.main_pw)
        self.authenticated = False
        self.buffer = ""
        self.latency = 10000
        self.i = initiator.register()
        self.idchar = (
            str(self.i) if 10 <= self.i <= 99 else '0' + str(self.i))
        self.cronjob = None
        self.cancel_job = None

    def generate_auth_msg(self):
        """Generate encrypted message. For auth and init.

        The message is in the form
            server_sign(main_pw) (HEX) +
            client_pub(session_pw) + id
        Total length is 512 + 256 + 2 = 770 bytes
        """
        hex_sign = '%X' % self.pri.sign(self.main_pw, None)[0]
        pw_enc = self.client_pub.encrypt(self.session_pw, None)[0]
        return hex_sign + pw_enc + self.idchar +\
            repr(self.initiator.client_recv_index_dict[self.i])

    def ping_send(self):
        """Send the initial ping message to the client at a certain interval.

        Ping mechanism (S for server, C for client, t-i for i-th timestamp):
            packet 0: S->C, t-0
            packet 1: C->S, t-0 + t-1
            packet 2: S->C, t-1
        In this way, both server and client get the round-trip latency.

        Packet format (before encryption):
            "1"         (1 byte)          (type flag for ping)
            seq         (1 byte)          (0, 1 or 2)
            timestamp   (11 or 22 bytes)  (time in milliseconds, in hexagon)
        """
        raw_packet = "1" + "0" + get_timestamp()
        to_write = self.cipher.encrypt(raw_packet) + self.split_char
        if self.authenticated:
            #logging.debug("send ping0")
            self.transport.write(to_write)
            interval = random.randint(500, 1500) / 100
            if self.initiator.obfs_level == 3:
                RESET_INTERVAL = 5
            else:
                RESET_INTERVAL = 2
            self.cronjob = reactor.callLater(interval, self.ping_send)
            self.cancel_job = reactor.callLater(RESET_INTERVAL, self.close)

    def ping_recv(self, msg):
        """Parse ping 1 (without flag & seq) and send ping 2."""
        #logging.debug("recv ping1")
        self.cancel_job.cancel()
        time0 = parse_timestamp(msg[:11])
        self.latency = int(time() * 1000) - time0
        logging.debug("latency: %dms" % self.latency)
        raw_packet = "1" + "2" + msg[11:]
        to_write = self.cipher.encrypt(raw_packet) + self.split_char
        if self.transport:
            #logging.debug("send ping2")
            self.transport.write(to_write)

    def connectionMade(self):
        """Event handler of being successfully connected to the client."""
        logging.info("connected to client " +
                     addr_to_str(self.transport.getPeer()))
        self.transport.write(self.generate_auth_msg() + self.split_char)

    def dataReceived(self, recv_data):
        """Event handler of receiving some data from client.

        Split, decrypt and hand them back to Control.
        """
        # Avoid repetition caused by ping
        # logging.debug("received %d bytes from client " % len(recv_data) +
        #              addr_to_str(self.transport.getPeer()))

        self.buffer += recv_data

        # a list of encrypted data packages
        # the last item may be incomplete
        recv = self.buffer.split(self.split_char)
        # leave the last (may be incomplete) item intact
        for text_enc in recv[:-1]:
            text_dec = self.cipher.decrypt(text_enc)
            # flag is 0 for normal data packet, 1 for ping packet, 2 for auth
            flag = int(text_dec[0])
            if flag == 0:
                self.initiator.client_recv(text_dec[1:], self)
            elif flag == 2:
                auth_str = "AUTHENTICATED" + self.idchar
                if text_dec[1:].startswith(auth_str):
                    max_recved_idx = eval(text_dec[1:].lstrip(auth_str))
                    self.authenticate_success()
                    self.initiator.retransmit_clientconn_reload(
                        self, max_recved_idx)
                else:
                    self.close()
            else:
                # strip off type and seq (both are always 1)
                self.ping_recv(text_dec[2:])

        self.buffer = recv[-1]  # incomplete message

    def authenticate_success(self):
        self.authenticated = True
        logging.debug("Authentication confirm string received.")
        self.initiator.add_cli(self)
        self.ping_send()

    def close(self):
        '''a secure way to abort the connection'''
        try:
            self.cronjob.cancel()
        except Exception:
            pass
        # self.initiator.remove_cli(self)
        self.transport.loseConnection()

    def connectionLost(self, reason):
        """Event handler of losing the connection to the client.

        Call Control to handle it.
        """
        if self.authenticated:
            logging.info("client connection lost: " +
                         addr_to_str(self.transport.getPeer()))
        self.authenticated = False
        self.initiator.client_lost(self)

    def write(self, data, conn_id, index):
        """Encrypt and write data the client.

        Encrypted packets should be separated by split_char.
        Raw packet structure:
            type    (1 byte)   (0 for normal data packet)
            id      (2 bytes)
            index   (6 bytes)
            data
        """

        to_write = self.cipher.encrypt("0" + conn_id + str(index) + data) +\
            self.split_char
        logging.debug("sending %d bytes to client %s with id %s" % (len(data),
                                                                    addr_to_str(
                                                                        self.transport.getPeer()),
                                                                    conn_id))
        self.transport.write(to_write)

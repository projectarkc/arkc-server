import logging
import dnslib
import hashlib
import binascii
import ipaddress
from twisted.internet import reactor
from twisted.internet.protocol import DatagramProtocol
from twisted.internet.endpoints import TCP4ClientEndpoint

from control import Control
import pyotp

MAX_SALT_BUFFER = 255

class ClientAddrChanged(Exception):
    pass

class Duplicateerror(Exception):
    pass

class CorruptedReq(Exception):
    pass

class Coordinator(DatagramProtocol):

    """Dispatch UDP requests to ClientConnectorCreators.

    The local http proxy port, Tor port, the server's private key,
    and a dict of trusted clients' public keys must be given.

    Pass None as tor_port if Tor is not needed.

    The dict maps SHA1 to key object.
    """


    def __init__(self, proxy_port, tor_port, pri, certs):
        self.proxy_port = proxy_port
        self.tor_port = tor_port
        self.pri = pri

        # dict mapping client sha-1 to (client pub, sha1(client pri))
        self.certs = certs

        # dict mapping client sha-1 to creator
        self.creators = dict()

        self.recentsalt = []

        # Create an endpoint of Tor
        if self.tor_port:
            host = "127.0.0.1"
            port = self.tor_port
            self.tor_point = TCP4ClientEndpoint(reactor, host, port)
        else:
            self.tor_point = None

    def decrypt_udp_msg(self, msg1, msg2, msg3, msg4, msg5):
        """Return (main_pw, client_sha1, number).

            The encrypted message should be
            (required_connection_number (HEX, 2 bytes) +
            used_remote_listening_port (HEX, 4 bytes) +
            sha1(cert_pub) ,
            pyotp.TOTP(time) , ## TODO: client identity must be checked
            main_pw,
            ip_in_number_form,
            salt
            Total length is 2 + 4 + 40 = 46, 16, 16, ?, 16
        """
        assert len(msg1) == 46

        if msg5 in self.recentsalt:
            return (None, None, None, None, None)

        number_hex, port_hex, client_sha1 = msg1[:2], msg1[2:6], msg1[6:46]
        remote_ip = str(ipaddress.ip_address(int(msg4)))
        h = hashlib.sha256()
        h.update(self.certs[client_sha1][1] + msg4 + msg5)
        assert msg2 == pyotp.TOTP(h.hexdigest()).now()
        main_pw = binascii.unhexlify(msg3)
        number = int(number_hex, 16)
        remote_port = int(port_hex, 16)
        if len(self.recentsalt) >= MAX_SALT_BUFFER:
            self.recentsalt.pop(0)
        self.recentsalt.append(msg5)
        return main_pw, client_sha1, number, remote_port, remote_ip

    def datagramReceived(self, data, addr):
        """Event handler of receiving a UDP request.

        Verify the identity of the client and assign a ClientConnectorCreator
        to it if it is trusted.
        """

        #Give a NXDOMAIN response

        logging.info("received DNS request from %s:%d" % (addr[0], addr[1]))
        try:
            dnsq = dnslib.DNSRecord.parse(data)
        except Exception as err:
            logging.info("Corrupted request")
        query_data = str(dnsq.q.qname).split('.')
        try:
            # One creator corresponds to one client (with a unique SHA1)
            # TODO: Use ip addr to support multiple conns

            if len(query_data) < 7:
                raise CorruptedReq

            main_pw, client_sha1, number, tcp_port, remote_ip = self.decrypt_udp_msg(query_data[0], query_data[1], query_data[2], query_data[3], query_data[4])
            if client_sha1 == None:
                raise Duplicateerror
            if client_sha1 not in self.creators:
                client_pub = self.certs[client_sha1][0]
                creator = Control(self, client_pub, self.certs[client_sha1][1], remote_ip, tcp_port,
                                  main_pw, number)
                self.creators[client_sha1] = creator
            else:
                creator = self.creators[client_sha1]
                if main_pw != creator.main_pw:
                    creator.main_pw = main_pw
                    logging.warning("main password changed")
                if remote_ip != creator.host or tcp_port != creator.port:
                    raise ClientAddrChanged

            creator.connect()

        except CorruptedReq:
            logging.info("Corrupted request")
        except Duplicateerror:
            pass  #TODO:should mimic DNS server
        except KeyError:
            logging.error("untrusted client")
        except AssertionError:
            logging.error("authentication failed or corrupted request")
        except ClientAddrChanged:
            logging.error("client address or port changed")
        except Exception as err:
            logging.error("unknown error: " + str(err))

import logging
import dnslib
import binascii
from twisted.internet import reactor
from twisted.internet.protocol import DatagramProtocol
from twisted.internet.endpoints import TCP4ClientEndpoint
from control import Control


class ClientAddrChanged(Exception):
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
        # dict mapping sha-1 to clients' public keys and creators
        self.certs = certs
        self.creators = dict()

        # Create an endpoint of Tor
        if self.tor_port:
            host = "127.0.0.1"
            port = self.tor_port
            self.tor_point = TCP4ClientEndpoint(reactor, host, port)
        else:
            self.tor_point = None

    def decrypt_udp_msg(self, msg):
        """Return (main_pw, client_sha1, number).

        The encrypted message should be
            salt +
            required_connection_number (HEX, 2 bytes) +
            client_listen_port (HEX, 4 bytes) +
            sha1(local_pub) +
            client_sign(salt) +
            server_pub(main_pw)
        Total length is 16 + 2 + 4 + 40 + 512 + 256 = 830 bytes
        """
        assert len(msg) == 830
        salt, number_hex, port_hex, client_sha1, salt_sign_hex, main_pw_enc = \
            msg[:16], msg[16:18], msg[18:22], msg[22:62], msg[62:574], \
            msg[574:]
        salt_sign = (binascii.unhexlify(salt_sign_hex))
        number = int(number_hex, 16)
        client_pub = self.certs[client_sha1]
        assert client_pub.verify(salt, salt_sign)
        main_pw = self.pri.decrypt(binascii.unhexlify(main_pw_enc))
        remote_port = int(port_hex, 16)
        return main_pw, client_sha1, number, remote_port

    def datagramReceived(self, data, addr):
        """Event handler of receiving a UDP request.

        Verify the identity of the client and assign a ClientConnectorCreator
        to it if it is trusted.
        """
        # TODO: UDP message may not come from the same host as client
        host, udp_port = addr
        logging.info("received udp request from %s:%d" % (host, udp_port))
        dnsq = dnslib.DNSQuestion.parse(data)
        query_data = dnsq.q.qname.split('.')[0]
        #print len(query_data)
        try:
            # One creator corresponds to one client (with a unique SHA1)
            main_pw, client_sha1, number, tcp_port = self.decrypt_udp_msg(query_data)
            if client_sha1 not in self.creators:
                client_pub = self.certs[client_sha1]
                creator = Control(self, client_pub, host, tcp_port,
                                  main_pw, number)
                self.creators[client_sha1] = creator
            else:
                creator = self.creators[client_sha1]
                if main_pw != creator.main_pw:
                    creator.main_pw = main_pw
                    logging.warning("main password changed")
                if host != creator.host or tcp_port != creator.port:
                    raise ClientAddrChanged

            creator.connect()

        except KeyError:
            logging.error("untrusted client")
        except AssertionError:
            logging.error("authentication failed")
        except ClientAddrChanged:
            logging.error("client address changed")
        except Exception as err:
            logging.error("unknown error: " + str(err))

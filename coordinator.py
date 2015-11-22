import logging
import dnslib
import binascii
import pyotp
import ipaddress
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

    def decrypt_udp_msg(self, msg1, msg2, msg3, msg4, msg5):
        """Return (main_pw, client_sha1, number).

            The encrypted message should be
            (required_connection_number (HEX, 2 bytes) +
            used_remote_listening_port (HEX, 4 bytes) +
            sha1(cert_pub) ,
            pyotp.HOTP(time) , ## TODO: client identity must be checked
            main_pw,
            ip_in_number_form,
            salt
            Total length is 2 + 4 + 40 = 46, 16, 16, ?, 16
        """
        # TODO: create a used salt list keeping updated against repplay DDoS
        
        assert len(msg1) == 46
        assert len(msg2) == 16
        assert len(msg3) == 16
        assert len(msg5) == 16
        number_hex, port_hex, client_sha1 = msg1[:2], msg1[2:6], msg1[6, 46]
        remote_ip = str(ipaddress.ip_address(msg4))
        assert msg2 == str(pyotp.TOTP(self.certs[client_sha1](1) + remote_ip + binascii.unhexlify(msg5)).now())
        main_pw = binascii.unhexlify(msg3)
        number = int(number_hex, 16)
        remote_port = int(port_hex, 16)
        
        return main_pw, client_sha1, number, remote_port, remote_ip

    def datagramReceived(self, data, addr):
        """Event handler of receiving a UDP request.

        Verify the identity of the client and assign a ClientConnectorCreator
        to it if it is trusted.
        """
        logging.info("received DNS request")
        dnsq = dnslib.DNSQuestion.parse(data)
        query_data = dnsq.q.qname.split('.')
        #print len(query_data)
        try:
            # One creator corresponds to one client (with a unique SHA1) 
            #TODO: Use ip addr to support multiple conns
            
            assert len(query_data) == 5
            
            main_pw, client_sha1, number, tcp_port, remote_ip = self.decrypt_udp_msg(query_data[0],query_data[1],query_data[2],query_data[3], query_data[4])
            if client_sha1 not in self.creators:
                client_pub = self.certs[client_sha1](0)
                creator = Control(self, client_pub, self.certs[client_sha1](1), remote_ip, tcp_port,
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

        except KeyError:
            logging.error("untrusted client")
        except AssertionError:
            logging.error("authentication failed or corrupted request")
        except ClientAddrChanged:
            logging.error("client address or port changed")
        except Exception as err:
            logging.error("unknown error: " + str(err))

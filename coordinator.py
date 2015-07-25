import logging
from twisted.internet import reactor
from twisted.internet.protocol import DatagramProtocol
from twisted.internet.endpoints import TCP4ClientEndpoint
from client import ClientConnectorCreator


class ClientAddrChanged(Exception):
    pass


class Coordinator(DatagramProtocol):

    """Dispatch UDP requests to ClientConnectorCreators.

    The local http proxy port, the server's private key,
    and a dictionary of trusted clients' public keys must be given.
    """

    def __init__(self, proxy_port, tor_port, pri, certs, client_port):
        self.proxy_port = proxy_port
        self.tor_port = tor_port
        self.pri = pri
        # dicts matching sha-1 to clients' public keys and creators
        self.certs = certs
        self.creators = dict()
        self.client_port = client_port
        # TODO: deprecate this parameter?

        if self.tor_port:
            host = "127.0.0.1"
            port = self.tor_port
            self.tor_point = TCP4ClientEndpoint(reactor, host, port)

    def decrypt_udp_msg(self, msg):
        """Return (main_pw, client_sha1).

        The encrypted message should be
            salt +
            required_connection_number (HEX, 2 bytes)
            sha1(local_pub) +
            client_sign(salt) +
            server_pub(main_pw)
        Total length is 16 + 2 + 40 + 512 + 256 = 826 bytes
        """
        assert len(msg) == 826
        salt, number_hex, client_sha1, salt_sign_hex, main_pw_enc = \
            msg[:16], msg[16:18], msg[18: 58], msg[58: 570], msg[570:]
        salt_sign = (int(salt_sign_hex, 16),)
        number = (int(number_hex, 16),)
        client_pub = self.certs[client_sha1]
        assert client_pub.verify(salt, salt_sign)
        main_pw = self.pri.decrypt(main_pw_enc)
        return main_pw, client_sha1, number

    def datagramReceived(self, data, addr):
        logging.info("received udp request from " + str(addr))
        host = addr[0]
        port = self.client_port
        try:
            main_pw, client_sha1, number= self.decrypt_udp_msg(data)
            if client_sha1 not in self.creators:
                client_pub = self.certs[client_sha1]
                creator = ClientConnectorCreator(
                    self, client_pub, host, port, main_pw)
            else:
                creator = self.creators[client_sha1]
                assert main_pw == creator.main_pw
                if host != creator.host or port != creator.port:
                    raise ClientAddrChanged
            while creator.number <= number:
                creator.connect()
        except KeyError:
            logging.error("untrusted client")
        except AssertionError:
            logging.error("authentication failed")
        except ClientAddrChanged:
            logging.error("client address changed")
        except Exception as err:
            raise err  # remove this line after debug
            logging.error("unknown error: " + str(err))

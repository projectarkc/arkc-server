import logging
from twisted.internet.protocol import DatagramProtocol
from client import ClientConnectorCreator


class ClientAddrChanged(Exception):
    pass


class Coordinator(DatagramProtocol):

    """Dispatch UDP requests to ClientConnectorCreators.

    The local http proxy port, the server's private key,
    and a dictionary of trusted clients' public keys must be given.
    """

    def __init__(self, proxy_port, pri, certs):
        self.proxy_port = proxy_port
        self.pri = pri
        # dicts matching sha-1 to clients' public keys and creators
        self.certs = certs
        self.creators = dict()

    def decrypt_udp_msg(self, msg):
        """Return (main_pw, client_sha1).

        The encrypted message should be
            salt +
            sha1(local_pub) +
            client_sign(salt) +
            server_pub(main_pw)
        Total length is 16 + 40 + 512 + 256 = 824 bytes
        """
        assert len(msg) == 824
        salt, client_sha1, salt_sign_hex, main_pw_enc = \
            msg[:16], msg[16: 56], msg[56: 568], msg[568:]
        salt_sign = (int(salt_sign_hex, 16),)
        client_pub = self.certs[client_sha1]
        assert client_pub.verify(salt, salt_sign)
        main_pw = self.pri.decrypt(main_pw_enc)
        return main_pw, client_sha1

    def datagramReceived(self, data, addr):
        logging.info("received udp request from " + str(addr))
        (host, port) = addr
        try:
            main_pw, client_sha1 = self.decrypt_udp_msg(data)
            if not self.creators.has_key[client_sha1]:
                client_pub = self.certs[client_sha1]
                creator = ClientConnectorCreator(
                    self, client_pub, host, port, main_pw)
            else:
                creator = self.creators[client_sha1]
                assert main_pw == creator.main_pw
                if host != creator.host or port != creator.port:
                    raise ClientAddrChanged
            creator.connect()
        except KeyError:
            logging.error("untrusted client")
        except AssertionError:
            logging.error("authentication failed")
        except ClientAddrChanged:
            logging.error("client address changed")
        except Exception as err:
            raise err
            logging.error("unknown error: " + str(err))

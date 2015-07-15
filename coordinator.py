import logging
from twisted.internet.protocol import DatagramProtocol
from client import ClientConnector


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
        """Return (salt, string, client_sha1).

        The encrypted message should be
            server_pub(
                salt +
                sha1(local_pub) +
                local_pri(salt + string)
            )
        """
        decrypted_msg = self.pri.decrypt(msg)
        salt = decrypted_msg[:16]
        client_sha1 = decrypted_msg[16: 36]
        client_pub = self.certs[client_sha1]
        salt_string = client_pub.decrypt(decrypted_msg[36:])
        salt1, string = salt_string[:16], salt_string[16:]
        assert salt == salt1
        assert len(string) == 16
        return salt, string, client_sha1

    def datagramReceived(self, data, addr):
        logging.info("received udp request from "+str(addr))
        host = addr.host
        port = addr.port
        try:
            salt, string, client_sha1 = self.decrypt_udp_msg(data)
            if not self.creators.has_key[client_sha1]:
                client_pub = self.certs[client_sha1]
                creator = ClientConnector(self, client_pub, host, port, string)
            else:
                creator = self.creators[client_sha1]
                assert string == creator.string
                if host != creator.host or port != creator.port:
                    logging.warning("client address changed")
            creator.connect(salt)
        except KeyError:
            logging.error("untrusted client")
        except AssertionError:
            logging.error("authentication information does not match")
        except Exception as err:
            logging.error("unknown error: " + err)

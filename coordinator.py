import logging
from twisted.internet import reactor
from twisted.internet.protocol import DatagramProtocol
from twisted.internet.endpoints import TCP4ClientEndpoint
import ipaddress

from control import Control

MAX_SALT_BUFFER = 255


class ClientAddrChanged(Exception):
    pass


class DuplicateError(Exception):
    pass


class CorruptedReq(Exception):
    pass


class Coordinator(DatagramProtocol):

    """Dispatch UDP requests to Controls.
    The local http proxy port, Tor port, the server's private key,
    and a dict of trusted clients' public keys must be given.
    Pass None as tor_port if Tor is not needed.
    The dict maps SHA1 to key object.
    """

    def __init__(self, proxy_port, tor_port, pri, cert,
                 delegatedomain, selfdomain, pt_exec, obfs_level):
        self.proxy_port = proxy_port
        self.tor_port = tor_port
        self.pri = pri
        self.delegatedomain = delegatedomain
        self.selfdomain = selfdomain
        self.pt_exec = pt_exec
        self.obfs_level = obfs_level
        self.usedports = []

        # dict mapping client sha-1 to (client pub, sha1(client pri))
        self.central_pub = cert

        # dict mapping client sha-1 to control
        self.controls = dict()

        self.recentsalt = []

        # Create an endpoint of Tor
        if self.tor_port:
            host = "127.0.0.1"
            port = self.tor_port
            self.tor_point = TCP4ClientEndpoint(reactor, host, port)
        else:
            self.tor_point = None

    def parse_udp_msg(self, msg):
        """Return (main_pw, client_sha1, number).
         The encrypted message should be
             salt +
             required_connection_number (HEX, 2 bytes) +
             client_listen_port (HEX, 4 bytes) +
             sha1(local_pub) +
             client_sign(salt) +
             server_pub(main_pw) +
             remote_ip
         Total length is 16 + 2 + 4 + 40 + 512 + 256 = 830 bytes
         """

        #assert len(msg) == 830
        salt, number_hex, port_hex, client_sha1, salt_sign_hex, main_pw_enc, remote_ip_enc = \
            msg[:16], msg[16:18], msg[18:22], msg[
                22:62], msg[62:574], (msg[574:])[:-7], msg[-7:]
        if salt in self.recentsalt:
            return (None, None, None, None)
        remote_ip = str(
            ipaddress.ip_address(int(remote_ip_enc.rstrip("="), 36)))
        salt_sign = (int(salt_sign_hex, 16),)
        number = int(number_hex, 16)
        remote_port = int(port_hex, 16)
        assert self.central_pub.verify(
            salt + str(number) + remote_ip_enc + str(remote_port), salt_sign)
        main_pw = self.pri.decrypt(main_pw_enc)
        if len(self.recentsalt) >= MAX_SALT_BUFFER:
            self.recentsalt.pop(0)
        self.recentsalt.append(salt)

        # if not self.obfs_level:
        #    certs_str = None
        # else:
        #    # ptproxy enabled
        #    certs_original = msg[5] + msg[6]
        #    certs_original += '=' * ((160 - len(certs_original)) % 4)
        #    certs_str = urlsafe_b64_short_decode(certs_original)
        certs_str = None

        return main_pw, client_sha1, number, remote_port, remote_ip, certs_str

    def datagramReceived(self, data, addr):
        """Event handler of receiving a UDP request.
        Verify the identity of the client and assign a Control
        to it if it is trusted.
        """
        logging.info("received DNS request from %s:%d" % (addr[0], addr[1]))

        try:
            main_pw, client_sha1, number, tcp_port, remote_ip, certs_str = \
                self.parse_udp_msg(data)
            if client_sha1 is None:
                raise DuplicateError
            if client_sha1 not in self.controls:
                client_pub = self.certs[client_sha1][0]
                control = Control(self, client_pub, self.certs[client_sha1][1],
                                  remote_ip, tcp_port,
                                  main_pw, number, certs_str)
                self.controls[client_sha1] = control
            else:
                control = self.controls[client_sha1]
                control.update(remote_ip, tcp_port, main_pw, number)

            control.connect()

        except CorruptedReq:
            logging.info("Corrupt request")
        except DuplicateError:
            pass  # TODO:should mimic DNS server
        except KeyError:
            logging.error("untrusted client")
        except AssertionError:
            logging.error("authentication failed or corrupt request")
        except ClientAddrChanged:
            logging.error("client address or port changed")
        # except Exception as err:
        #    logging.error("unknown error: " + str(err))

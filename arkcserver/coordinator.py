import logging
import dnslib
import hashlib
import ipaddress
import binascii
from twisted.internet import reactor
from twisted.internet.protocol import DatagramProtocol
from twisted.internet.endpoints import TCP4ClientEndpoint

from control import Control
import pyotp

from utils import urlsafe_b64_short_decode

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

    def __init__(self, proxy_port, socksproxy, pri, certs_db,
                 central_cert, delegatedomain, selfdomain, pt_exec,
                 obfs_level, meek_url, transmit):
        self.proxy_port = proxy_port
        self.socksproxy = socksproxy
        self.pri = pri
        self.delegatedomain = delegatedomain
        self.selfdomain = selfdomain
        self.pt_exec = pt_exec
        self.obfs_level = obfs_level
        self.usedports = []
        self.meek_url = meek_url
        self.transmit = transmit
        self.central_pub = central_cert
        # dict mapping client sha-1 to (client pub, sha1(client pri))
        self.certs_db = certs_db

        # dict mapping client sha-1 to control
        self.controls = dict()

        self.recentsalt = []

    def parse_udp_msg(self, *msg):
        """
        Return (main_pw, sha1, num, port, ip, [certs_str or None]).

        `certs_str` is available only when ptproxy is enabled.

        The message should be
            (
                required_connection_number (HEX, 2 bytes) +
                    used_remote_listening_port (HEX, 4 bytes) +
                    sha1(cert_pub),
                pyotp.TOTP(pri_sha1 + ip_in_hex_form + salt),   # TODO: client identity must be checked
                main_pw,
                ip_in_hex_form,
                salt,
                [cert1,
                cert2   (only when obfs4 is enabled)],
                [some random string (only when meek is enabled)]
            )
        """

        assert len(msg[0]) == 46    # 2 + 4 + 40

        if msg[4] in self.recentsalt:
            return None, None, None, None, None, None

        num_hex, port_hex, client_sha1 = msg[0][:2], msg[0][2:6], msg[0][6:46]
        h = hashlib.sha256()
        cert = self.certs_db.query(client_sha1)
        if cert is None:
            raise CorruptedReq
        h.update(cert[1] + msg[3] + msg[4] + num_hex)
        assert msg[1] == pyotp.TOTP(h.hexdigest()).now()
        if msg[3][-1:] != 'G':
            remote_ip = str(ipaddress.ip_address(int(msg[3], 36)))
        else:
            remote_ip = str(ipaddress.IPv6Address(int(msg[3][:-1], 36)))
        main_pw = binascii.unhexlify(msg[2])
        number = int(num_hex, 16)
        if number <= 0:
            number = None
        remote_port = int(port_hex, 16)
        if len(self.recentsalt) >= MAX_SALT_BUFFER:
            self.recentsalt.pop(0)
        self.recentsalt.append(msg[4])

        if 1 <= self.obfs_level <= 2:
            # obfs4 enabled
            certs_original = msg[5] + msg[6]
            certs_original += '=' * ((160 - len(certs_original)) % 4)
            certs_str = urlsafe_b64_short_decode(certs_original)
        else:
            certs_str = None

        return main_pw, client_sha1, number, remote_port, remote_ip, certs_str

    def parse_udp_msg_transmit(self, msg):
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

    def answer(self, dnsq, addr):
        answer = dnsq.reply()
        answer.header = dnslib.DNSHeader(id=dnsq.header.id,
                                         aa=1, qr=1, ra=1, rcode=3)
        answer.add_auth(
            dnslib.RR(
                self.delegatedomain,
                dnslib.QTYPE.SOA,
                ttl=3600,
                rdata=dnslib.SOA(
                    self.selfdomain,
                    "webmaster." + self.selfdomain,
                    (20130101, 3600, 3600, 3600, 3600)
                )
            )
        )
        answer.set_header_qa()
        packet = answer.pack()
        self.transport.write(packet, addr)

    def datagramReceived(self, data, addr):
        """Event handler of receiving a UDP request.
        Verify the identity of the client and assign a Control
        to it if it is trusted.
        """
        logging.debug("received DNS request from %s:%d" % (addr[0], addr[1]))

        if not self.transmit:
            try:
                dnsq = dnslib.DNSRecord.parse(data)
                query_data = str(dnsq.q.qname).split('.')
                # Give a NXDOMAIN response
                self.answer(dnsq, addr)
            except KeyError:
                logging.info("Corrupt request")

        try:
            # One control corresponds to one client (with a unique SHA1)

            # TODO: get obfs level from query length

            if self.transmit:
                main_pw, client_sha1, number, tcp_port, remote_ip, certs_str = \
                    self.parse_udp_msg_transmit(data)
            else:
                main_pw, client_sha1, number, tcp_port, remote_ip, certs_str = \
                    self.parse_udp_msg(*query_data[:6])
            if number is None:
                raise CorruptedReq
            if client_sha1 not in self.controls:
                cert = self.certs_db.query(client_sha1)
                control = Control(self, client_sha1, cert[0], cert[1],
                                  remote_ip, tcp_port,
                                  main_pw, number, certs_str)
                self.controls[client_sha1] = control
            else:
                control = self.controls[client_sha1]
                control.update(remote_ip, tcp_port, main_pw, number)

            control.connect()

        except CorruptedReq:
            logging.info("Corrupt request")
        except KeyError:
            logging.error("untrusted client")
        except AssertionError:
            logging.error("authentication failed or corrupt request")
        except ClientAddrChanged:
            logging.error("client address or port changed")
        # except Exception as err:
        #    logging.error("unknown error: " + str(err))

    def remove_ctl(self, client_sha1):
        try:
            del self.controls[client_sha1]
            self.controls.pop(client_sha1)
        except Exception:
            pass

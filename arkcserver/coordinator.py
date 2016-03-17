#!/usr/bin/env python
# coding:utf-8

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

from utils import urlsafe_b64_short_decode, int2base

MAX_SALT_BUFFER = 255
BLACKLIST_EXPIRE_TIME = 7200
MAX_CONN_PER_CLIENT = 20


class DuplicateError(Exception):
    pass


class CorruptedReq(Exception):
    pass


class IllegalReq(Exception):
    pass


class BlacklistReq(Exception):
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

        # dict mapping <client sha-1> + <main_pw> to control,
        self.controls = dict()

        self.recentsalt = []
        self.blacklist = []
        self.blacklist_buffer = dict()

    def parse_udp_msg(self, *msg):
        """
        Return (main_pw, sha1, num, port, ip, [certs_str or None]).

        `certs_str` is available only when ptproxy is enabled.

        The message should be
            (
                required_connection_number (HEX, 2 bytes) +
                    used_remote_listening_port (HEX, 4 bytes) +
                    sha1(cert_pub) + version (ascii, 2 bytes),
                pyotp.TOTP(pri_sha1 + ip_in_hex_form + salt),   # TODO: client identity must be checked
                main_pw,
                ip_in_hex_form,
                salt,
                [cert1,
                cert2   (only when obfs4 is enabled)],
                [some random string (only when meek is enabled)]
            )
        """

        assert len(msg[0]) == 48    # 2 + 4 + 40 + 2

        if msg[4] in self.recentsalt:
            raise BlacklistReq
        num_hex, port_hex, client_sha1, version = msg[0][
            :2], msg[0][2:6], msg[0][6:46], msg[0][46:48]
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
            raise CorruptedReq
        remote_port = int(port_hex, 16)
        if len(self.recentsalt) >= MAX_SALT_BUFFER:
            self.recentsalt.pop(0)
        self.recentsalt.append(msg[4])
        if (client_sha1 + main_pw) in self.blacklist:
            raise BlacklistReq
        if number > MAX_CONN_PER_CLIENT:
            raise IllegalReq

        if 1 <= self.obfs_level <= 2:
            # obfs4 enabled
            certs_original = msg[5] + msg[6]
            certs_original += '=' * ((160 - len(certs_original)) % 4)
            certs_str = urlsafe_b64_short_decode(certs_original)
        else:
            certs_str = None
        signature_to_client = int2base(self.pri.sign(main_pw, None)[0])
        return main_pw, client_sha1, number, remote_port, remote_ip, certs_str, signature_to_client

    def parse_udp_msg_transmit(self, msg):
        """Return (main_pw, client_sha1, number).
         The encrypted message should be
             salt \r\n
             required_connection_number (HEX, 2 bytes) \r\n
             client_listen_port (HEX, 4 bytes) \r\n
             sha1(local_pub) \r\n
             client_sign(salt) \r\n
             server_pub(main_pw) \r\n
             remote_ip \r\n
             signature_to_client \r\n
             version
        """

        msglist = msg.split('\r\n')
        if len(msglist) != 9:
            raise CorruptedReq
        [salt, number_hex, port_hex, client_sha1,
         salt_sign_hex, main_pw_enc, remote_ip_enc] = msglist
        if salt in self.recentsalt:
            return BlacklistReq
        remote_ip = str(
            ipaddress.ip_address(int(remote_ip_enc.rstrip("="), 36)))
        salt_sign = (int(salt_sign_hex, 36),)
        number = int(number_hex, 16)
        if number > MAX_CONN_PER_CLIENT:
            raise IllegalReq
        remote_port = int(port_hex, 16)
        assert self.central_pub.verify(
            salt + str(number) + remote_ip_enc + str(remote_port), salt_sign)
        main_pw = self.pri.decrypt(main_pw_enc)
        if len(main_pw) != 16:
            raise CorruptedReq
        if len(self.recentsalt) >= MAX_SALT_BUFFER:
            self.recentsalt.pop(0)
        self.recentsalt.append(salt)
        if (client_sha1 + main_pw) in self.blacklist:
            raise BlacklistReq
        # if not self.obfs_level:
        #    certs_str = None
        # else:
        #    # ptproxy enabled
        #    certs_original = msg[5] + msg[6]
        #    certs_original += '=' * ((160 - len(certs_original)) % 4)
        #    certs_str = urlsafe_b64_short_decode(certs_original)
        certs_str = None
        signature_to_client = msglist[7]
        version = msglist[8]
        return main_pw, client_sha1, number, remote_port, remote_ip, certs_str, signature_to_client

    def answer(self, dnsq, addr):
        q_contents = str(dnsq.q.get_qname())
        
        if self.delegatedomain in q_contents:
            delegatedomain = self.delegatedomain
            selfdomain = self.selfdomain
        else:
            try:
                q_contents_split = q_contents.split('.')
                delegatedomain = '.'.join(q_contents_split[-5:])
                selfdomain = '.'.join([q_contents_split[-5]] + q_contents_split[-3:])
            except Exception:
                delegatedomain = self.delegatedomain
                selfdomain = self.selfdomain
        if dnsq.q.qtype == dnslib.QTYPE.MX:
            answer = dnsq.reply(ra=1, aa=1)
            answer.add_answer(
                *dnslib.RR.fromZone(q_contents + " 3600 MX 10 " + selfdomain))
        else:
            answer = dnsq.reply()
            answer.header = dnslib.DNSHeader(id=dnsq.header.id,
                                             aa=1, qr=1, ra=1, rcode=3)
            answer.add_auth(
                dnslib.RR(
                    delegatedomain,
                    dnslib.QTYPE.SOA,
                    ttl=3600,
                    rdata=dnslib.SOA(
                        selfdomain,
                        "webmaster." + selfdomain,
                                    (20130101, 3600,
                                     3600, 3600, 3600)
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
                main_pw, client_sha1, number, tcp_port, remote_ip, certs_str, signature = \
                    self.parse_udp_msg_transmit(data)
            else:
                main_pw, client_sha1, number, tcp_port, remote_ip, certs_str, signature = \
                    self.parse_udp_msg(*query_data[:6])
            if (client_sha1 + main_pw) not in self.controls:
                cert = self.certs_db.query(client_sha1)
                control = Control(self, signature, client_sha1, cert[0], cert[1],
                                  remote_ip, tcp_port,
                                  main_pw, number, certs_str)
                self.controls[client_sha1 + main_pw] = control
            else:
                control = self.controls[client_sha1 + main_pw]
                control.update(remote_ip, tcp_port, number)

            control.connect()

        except CorruptedReq:
            logging.debug("corrupt request")
        except KeyError:
            logging.warning("untrusted client attempting to connect")
        except AssertionError:
            logging.debug("authentication failed or corrupt request")
        except BlacklistReq:
            logging.debug("request or salt on blacklist")
        except IllegalReq:
            logging.debug("request for too many connections")

    def remove_ctl(self, client_sha1, main_pw):
        '''Remove reference to the Control instance'''
        try:
            del self.controls[client_sha1 + main_pw]
            self.controls.pop(client_sha1 + main_pw)
        except Exception:
            pass

    def blacklist_add(self, client_sha1, main_pw):
        self.blacklist.append(client_sha1 + main_pw)
        logging.warning(
            "New blacklist item added: " + client_sha1 + " | " + main_pw)
        reactor.callLater(
            BLACKLIST_EXPIRE_TIME, self.blacklist_expire, len(self.blacklist) - 1)

    def blacklist_expire(self, i):
        self.blacklist.pop(i)

    def blacklist_count(self, client_sha1, main_pw):
        if (client_sha1 + main_pw) not in self.blacklist:
            if (client_sha1 + main_pw) in self.blacklist_buffer:
                self.blacklist_buffer[client_sha1 + main_pw] += 1
                if self.blacklist_buffer[client_sha1 + main_pw] >= 10:
                    self.blacklist_add(client_sha1, main_pw)
                    self.blacklist_buffer.pop(client_sha1 + main_pw)
            else:
                self.blacklist_buffer[client_sha1 + main_pw] = 1

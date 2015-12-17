import logging
import dnslib
import hashlib
import binascii
import ipaddress
import base64
from twisted.internet import reactor
from twisted.internet.protocol import DatagramProtocol
from twisted.internet.endpoints import TCP4ClientEndpoint

from control import Control, Control_pt
import pyotp

MAX_SALT_BUFFER = 255

class ClientAddrChanged(Exception):
    pass

class Duplicateerror(Exception):
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


    def __init__(self, proxy_port, tor_port, pri, certs, delegatedomain, selfdomain):
        self.proxy_port = proxy_port
        self.tor_port = tor_port
        self.pri = pri
        self.delegatedomain=delegatedomain
        self.selfdomain=selfdomain

        # dict mapping client sha-1 to (client pub, sha1(client pri))
        self.certs = certs

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

    def decrypt_udp_msg(self, *msg):
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
        assert len(msg[0]) == 46

        if msg[4] in self.recentsalt:
            return (None, None, None, None, None)

        number_hex, port_hex, client_sha1 = msg[0][:2], msg[0][2:6], msg[0][6:46]
        remote_ip = str(ipaddress.ip_address(int(msg[3])))
        h = hashlib.sha256()
        h.update(self.certs[client_sha1][1] + msg[3] + msg[4])
        assert msg[1] == pyotp.TOTP(h.hexdigest()).now()
        main_pw = binascii.unhexlify(msg[2])
        number = int(number_hex, 16)
        remote_port = int(port_hex, 16)
        if len(self.recentsalt) >= MAX_SALT_BUFFER:
            self.recentsalt.pop(0)
        self.recentsalt.append(msg[4])
        return main_pw, client_sha1, number, remote_port, remote_ip

    def datagramReceived(self, data, addr):
        """Event handler of receiving a UDP request.
        Verify the identity of the client and assign a Control
        to it if it is trusted.
        """

        #Give a NXDOMAIN response

        logging.info("received DNS request from %s:%d" % (addr[0], addr[1]))
        try:
            dnsq = dnslib.DNSRecord.parse(data)
            query_data = str(dnsq.q.qname).split('.')
            #if query_data.q.qtype="SOA":
            #    packet=dnslib.DNSRecord(header=dnslib.DNSHeader(id=dnsq.header.id, aa=1, qr=1, ra=1)).pack()
            answer=dnsq.reply()
            answer.header=dnslib.DNSHeader(id=dnsq.header.id, aa=1, qr=1, ra=1, rcode=3)
            answer.add_auth(dnslib.RR(self.delegatedomain,dnslib.QTYPE.SOA,ttl=3600,
                            rdata=dnslib.SOA(self.selfdomain, "webmaster." + self.selfdomain, (20150101,3600,3600,3600,3600))))
            answer.set_header_qa()
            packet=answer.pack()
            self.transport.write(packet, addr)
        except KeyError as err:
            logging.info("Corrupted request")
            
        try:
            # One control corresponds to one client (with a unique SHA1)
            # TODO: Use ip addr to support multiple conns

            if len(query_data) < 7:
                raise CorruptedReq

            main_pw, client_sha1, number, tcp_port, remote_ip = \
                self.decrypt_udp_msg(*query_data[:5])
            if client_sha1 == None:
                raise Duplicateerror
            if client_sha1 not in self.controls:
                client_pub = self.certs[client_sha1][0]
                control = Control(self, client_pub, self.certs[client_sha1][1], remote_ip, tcp_port,
                                  main_pw, number)
                self.controls[client_sha1] = control
            else:
                control = self.controls[client_sha1]
                control.update(remote_ip, tcp_port,main_pw, number)

            control.connect()

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

class Coordinator_pt(DatagramProtocol):

    """Dispatch UDP requests to Controls.

    The local http proxy port, Tor port, the server's private key,
    and a dict of trusted clients' public keys must be given.

    Pass None as tor_port if Tor is not needed.

    The dict maps SHA1 to key object.
    """

    def __init__(self, proxy_port, tor_port, pri, certs, delegatedomain, selfdomain, pt_exec):
        self.proxy_port = proxy_port
        self.tor_port = tor_port
        self.pri = pri
        self.delegatedomain = delegatedomain
        self.selfdomain = selfdomain
        self.usedports = []
        self.pt_exec = pt_exec
        # dict mapping client sha-1 to (client pub, sha1(client pri))
        self.certs = certs

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

    def decrypt_udp_msg(self, *msg):
        """Return (main_pw, client_sha1, number).

            The encrypted message should be
            (required_connection_number (HEX, 2 bytes) +
            used_remote_listening_port (HEX, 4 bytes) +
            sha1(cert_pub) ,
            pyotp.TOTP(time) , ## TODO: client identity must be checked
            main_pw,
            ip_in_hex_form,
            cert1,
            cert2,
            cert3,
            salt
            Total length is 2 + 4 + 40 = 46, 16, 16, ?, 50, 50, 40, 16
        """
        assert len(msg[0]) == 46

        if msg[4] in self.recentsalt:
            return (None, None, None, None, None)

        number_hex, port_hex, client_sha1 = msg[0][:2], msg[0][2:6], msg[0][6:46]
        h = hashlib.sha256()
        h.update(self.certs[client_sha1][1] + msg[3] + msg[6])
        assert msg[1] == pyotp.TOTP(h.hexdigest()).now()
        remote_ip = str(ipaddress.ip_address(int(msg[3], 16)))
        main_pw = binascii.unhexlify(msg[2])
        number = int(number_hex, 16)
        remote_port = int(port_hex, 16)
        if len(self.recentsalt) >= MAX_SALT_BUFFER:
            self.recentsalt.pop(0)
        self.recentsalt.append(msg[6])
        certs_original = msg[4] + msg[5]
        certs_original = certs_original + '=' * ((160 - len(certs_original)) % 4)
        certs_str = base64.b64decode(certs_original)
        return main_pw, client_sha1, number, remote_port, remote_ip, certs_str

    def datagramReceived(self, data, addr):
        """Event handler of receiving a UDP request.

        Verify the identity of the client and assign a Control
        to it if it is trusted.
        """

        # Give a NXDOMAIN response
        logging.info("received DNS request from %s:%d" % (addr[0], addr[1]))
        try:
            dnsq = dnslib.DNSRecord.parse(data)
            query_data = str(dnsq.q.qname).split('.')
            # if query_data.q.qtype="SOA":
            #    packet=dnslib.DNSRecord(header=dnslib.DNSHeader(id=dnsq.header.id, aa=1, qr=1, ra=1)).pack()
            answer = dnsq.reply()
            answer.header = dnslib.DNSHeader(id=dnsq.header.id, aa=1, qr=1, ra=1, rcode=3)
            answer.add_auth(dnslib.RR(self.delegatedomain, dnslib.QTYPE.SOA, ttl=3600,
                            rdata=dnslib.SOA(self.selfdomain, "webmaster." + self.selfdomain, (20150101, 3600, 3600, 3600, 3600))))
            answer.set_header_qa()
            packet = answer.pack()
            self.transport.write(packet, addr)
        except KeyError as err:
            logging.info("Corrupted request")
            
        try:
            # One control corresponds to one client (with a unique SHA1)
            # TODO: Use ip addr to support multiple conns

            if len(query_data) < 9:
                raise CorruptedReq

            main_pw, client_sha1, number, tcp_port, remote_ip, certs_str = \
                self.decrypt_udp_msg(*query_data[:7])
            if client_sha1 == None:
                raise Duplicateerror
            if client_sha1 not in self.controls:
                client_pub = self.certs[client_sha1][0]
                control = Control_pt(self, client_pub, self.certs[client_sha1][1], remote_ip, tcp_port,
                                  main_pw, number, certs_str)
                self.controls[client_sha1] = control
            else:
                control = self.controls[client_sha1]
                control.update(remote_ip, tcp_port, main_pw, number)

            control.connect()

        except CorruptedReq:
            logging.info("Corrupted request")
        except Duplicateerror:
            pass
        except KeyError:
            logging.error("untrusted client")
        except AssertionError:
            logging.error("authentication failed or corrupted request")
        except ClientAddrChanged:
            logging.error("client address or port changed")
        except Exception as err:
            logging.error("unknown error: " + str(err))

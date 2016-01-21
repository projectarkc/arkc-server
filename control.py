import logging
from random import expovariate
from utils import weighted_choice
from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from txsocksx.client import SOCKS5ClientEndpoint as SOCKS5Point
from txsocksx.client import SOCKS4ClientEndpoint as SOCKS4Point
import time
import threading
import random
import os
import sys

from proxy import ProxyConnector
from utils import addr_to_str
from client import ClientConnector
from meekserver import meekinit
import psutil
import atexit
EXPIRE_TIME = 5


def exit_handler():

    for proc in psutil.process_iter():
        # check whether the process name matches
        # TODO: figure out what's wrong with PT_PROC
        if proc.name() == "obfs4proxy" or proc.name() == "obfs4proxy.exe"\
                or proc.name() == "meek-client" or proc.name() == "meek-client.exe":
            proc.kill()


class Control:
    """The core part of the server, acting as a bridge between client and proxy.

    One Control instance corresponds to one client (with unique SHA1).
    Its functions include:
        - Maintain a certain number of connections to client
            through ClientConnectors, as specified in UDP message.
        - Reset and re-connect at a random period (between 30 to 90 secs),
            for better performance.
        - Stash request data from client. Create ProxyConnectors on demand,
            through which to send the data.
        - Stash reponse data from proxy. Pick a connection to client to
            send them back.
    The Control itself is passed to both ClientConnectors and ProxyConnectors
        spawned from it as the `initiator` parameter.
    """

    def __init__(self, initiator, client_pub, client_pri_sha1, host, port,
                 main_pw, req_num, certs_str=None):
        self.initiator = initiator
        self.close_char = chr(4) * 5
        self.tor_point = self.initiator.tor_point
        self.obfs_level = self.initiator.obfs_level
        self.client_pub = client_pub
        self.client_pri_sha1 = client_pri_sha1
        self.original_host = self.host = host
        self.original_port = self.port = port
        self.main_pw = main_pw
        self.req_num = req_num
        self.certs_str = certs_str
        self.number = 0
        self.max_retry = 5
        self.retry_count = 0
        self.client_connectors = []

        # maps ID to decrypted data segments
        self.proxy_write_queues = dict()
        self.proxy_write_queues_index = dict()

        self.client_write_queues_index = dict()

        # maps ID to ProxyConnectors
        self.proxy_connectors = dict()

        # Create an endpoint for the HTTP proxy
        host, port = "127.0.0.1", self.initiator.proxy_port
        self.proxy_point = TCP4ClientEndpoint(reactor, host, port)

        # ptproxy enabled
        if self.certs_str:
            self.ptproxy_local_port = random.randint(30000, 40000)
            while self.ptproxy_local_port in initiator.usedports:
                self.ptproxy_local_port += 1
            initiator.usedports.append(self.ptproxy_local_port)
            pt = threading.Thread(
                target=self.ptinit)
            pt.setDaemon(True)
            self.check = threading.Event()
            pt.start()
            self.check.wait(100)

        if self.obfs_level == 3:
            self.ptproxy_local_port = None
            self.check = threading.Event()
            meek_var = {
                "ptexec": self.initiator.pt_exec +
                " --url=" + self.initiator.meek_url +
                " --desturl=http://" + self.host + ":" + str(self.port) + "/",
                "localport": self.ptproxy_local_port,
                "LOCK": self.check
            }
            pt = threading.Thread(
                target=meekinit, args=[self, meek_var])
            pt.setDaemon(True)
            pt.start()
            self.check.wait(100)

    # TODO: This pt is not working
    def ptinit(self):
        atexit.register(exit_handler)
        path = os.path.split(os.path.realpath(sys.argv[0]))[0]
        with open(path + os.sep + "ptserver.py") as f:
            code = compile(f.read(), "ptserver.py", 'exec')
            globals = {
                "SERVER_string": self.host + ":" + str(self.port),
                "ptexec": self.initiator.pt_exec + " -logLevel=ERROR",
                "localport": self.ptproxy_local_port,
                "remoteaddress": self.host,
                "remoteport": self.port,
                "certs": self.certs_str,
                "LOCK": self.check,
                "IAT": self.initiator.obfs_level
            }
            self.host = "127.0.0.1"
            self.port = self.ptproxy_local_port
            exec(code, globals)

    def update(self, host, port, main_pw, req_num):
        if self.original_host != host or self.original_port != port:
            if not self.obfs_level:
                self.original_host = self.host = host
                self.original_port = self.port = port
                logging.info("client address change")
            else:
                logging.error("pt mode does not allow client address change")
        self.req_num = req_num
        if self.main_pw != main_pw:
            self.main_pw = main_pw
            logging.info("main password change")

    def connect(self):
        """Connect client."""
        if self.number < self.req_num:

            # pre-add the available connection count
            # will be decremented if failure occurs
            self.number += 1

            connector = ClientConnector(self)

            # connect through Tor if required, direct connection otherwise
            if self.tor_point:
                point = SOCKS5Point(self.host, self.port, self.tor_point)
            elif self.obfs_level == 3:
                meek_point = TCP4ClientEndpoint(
                    reactor, "127.0.0.1", self.ptproxy_local_port)
                point = SOCKS4Point(self.host, self.port, meek_point)
            else:
                point = TCP4ClientEndpoint(reactor, self.host, self.port)

            deferred = connectProtocol(point, connector)
            # trigger success or failure action depending on the result
            deferred.addCallback(self.success)
            deferred.addErrback(lambda ignored: self.retry())

    def retry(self):
        """Triggered when a failure connecting client occurs.

        Decrement the number of available connections
        (which is pre-added when trying to connect),
        and retry until the max retry count is reached.
        """
        self.number -= 1
        if self.retry_count < self.max_retry:
            host, port = self.host, self.port
            logging.warning("retry connection to %s:%d" % (host, port))
            self.retry_count += 1
            self.connect()

    def success(self, conn):
        """Triggered when successfully connected to client.

        Reset retry count and continue adding connections until the required
        available connection number (specified by client through UDP message)
        is reached.
        Reset the connection after a random time for better performance.
        """
        self.retry_count = 0
        reactor.callLater(5, self.conn_check, conn)
        # Recheck
        self.connect()

    def conn_check(self, conn):
        """Test whether a connection is authenticated"""
        if conn:
            if conn.authenticated:
                # Reset the connection after a random time
                expire_time = expovariate(1.0 / 60)
                reactor.callLater(expire_time, self.client_reset, conn)
            else:
                conn.close()
                self.number -= 1
            # TODO: ADD to some black list?

    def add(self, conn):
        self.client_connectors.append(conn)

    def new_proxy_conn(self, conn_id):
        """Create a connection to HTTP proxy corresponding to the given ID.

        Return a Deferred object of the proxy connector.
        """
        logging.info("adding connection id " + conn_id)
        try:
            assert conn_id not in self.proxy_write_queues
            self.proxy_write_queues[conn_id] = dict()
            self.proxy_write_queues_index[conn_id] = 100
            self.proxy_connectors[conn_id] = ProxyConnector(self, conn_id)
            point, connector = self.proxy_point, self.proxy_connectors[conn_id]
            d = connectProtocol(point, connector)
            d.addCallback(lambda ignored: self.proxy_write(conn_id))
            d.addErrback(lambda ignored: logging.error("cannot connect proxy"))
        except AssertionError:
            logging.error("duplicate id")

    def del_proxy_conn(self, conn_id):
        """Remove the given ID.

        Triggered when the ID is no longer in use.
        """
        logging.info("deleting connection id " + conn_id)
        try:
            assert self.proxy_write_queues.pop(conn_id, None) is not None
            assert self.client_write_queues_index.pop(
                conn_id, None) is not None
            assert conn_id in self.proxy_connectors
            self.proxy_connectors.pop(conn_id).transport.loseConnection()
        except AssertionError:
            logging.warning("deleting non-existing key %s" % conn_id)

    def client_recv(self, recv):
        """Handle request from client.

        Should be decrypted by ClientConnector first.
        """
        conn_id, index, data = recv[:2], int(recv[2:5]), recv[5:]
        logging.debug("received %d bytes from client key " % len(data) +
                      conn_id)
        if data == self.close_char:
            # close connection and remove the ID
            if conn_id in self.proxy_connectors:
                conn = self.proxy_connectors[conn_id]
                if not conn.transport:
                    self.proxy_lost(conn_id)
                else:
                    conn.transport.loseConnection()
            else:
                logging.warning("closing non-existing connection")

        else:
            if conn_id not in self.proxy_connectors:
                self.new_proxy_conn(conn_id)
                self.proxy_write_queues[conn_id][index] = data
                # proxy_write called later
            else:
                self.proxy_write_queues[conn_id][index] = data
                self.proxy_write(conn_id)

    def client_write(self, data, conn_id):
        """Pick a client connector and write the data.
        Triggered by proxy_recv or proxy_finish.
        """

        i = 0
        while i <= 5 and len(self.client_connectors) == 0:
            time.sleep(0.02)
            i += 1
        assert len(self.client_connectors) != 0
        if conn_id not in self.client_write_queues_index:
            self.client_write_queues_index[conn_id] = 100
        if len(self.client_connectors) > 0:
            # TODO: better algorithm
            f = lambda c: 1.0 / (c.latency ** 2 + 1)
            conn = weighted_choice(self.client_connectors, f)
            conn.latency += 100
            conn.write(data, conn_id, self.client_write_queues_index[conn_id])
            self.client_write_queues_index[conn_id] += 1
            if self.client_write_queues_index[conn_id] == 1000:
                self.client_write_queues_index[conn_id] = 100
        else:
            logging.error(
                "no client_connectiors available, %i dumped." % len(data))

    def client_reset(self, conn):
        """Called after a random time to reset a existing connection to client.

        May result in better performance.
        """
        if conn.authenticated:
            conn.cronjob.cancel()
        self.client_lost(conn)
        if self.obfs_level != 3:
            conn.write(self.close_char, "00", 100)
        else:
            conn.close()

    def client_lost(self, conn):
        """Triggered by a ClientConnector's connectionLost method.

        Remove the closed connection and retry creating it.
        """
        if conn in self.client_connectors:
            self.client_connectors.remove(conn)
            self.number -= 1

        # TODO: need to redesign the counting method, connection to a proxy
        # will always success and then be lost when the actual client is down.
        if self.obfs_level == 0:
            self.connect()

    def proxy_write(self, conn_id):
        """Forward all the data pending for the ID to the HTTP proxy."""

        while conn_id in self.proxy_write_queues and self.proxy_write_queues_index[conn_id] in self.proxy_write_queues[conn_id]:
            data = self.proxy_write_queues[conn_id].pop(
                self.proxy_write_queues_index[conn_id])
            self.next_write_index(conn_id)
            if data is not None and len(data) > 0:
                conn = self.proxy_connectors[conn_id]
                if not conn.transport:
                    self.proxy_lost(conn_id)
                else:
                    logging.debug("sending %d bytes to proxy %s from id %s" % (
                        len(data),
                        addr_to_str(conn.transport.getPeer()),
                        conn_id))
                    conn.transport.write(data)

    def proxy_recv(self, data, conn_id):
        """Call client_write on receiving data from proxy."""
        try:
            self.client_write(data, conn_id)
        except AssertionError:
            logging.error(
                "%i dumped from proxy for no connections with the client" %
                len(data))
            logging.error("related proxy connection closing")
            self.proxy_lost(conn_id)
        # TODO: Are all proxy connections closed correctly? Keep-alive ones?

    def proxy_lost(self, conn_id):
        """Deal with the situation when proxy connection is lost unexpectedly.

        That is when conn.transport becomes None.
        """
        # TODO: why does this happen?
        conn = self.proxy_connectors[conn_id]
        conn.dead = True
        logging.warning("proxy connection %s lost unexpectedly" % conn_id)
        conn.respond()
        self.proxy_finish(conn_id)

    def proxy_finish(self, conn_id):
        """Write all pending response data to client and remove ID.

        Called when proxy connection is lost.
        """
        if len(self.client_connectors) != 0:
            self.client_write(self.close_char, conn_id)
        self.del_proxy_conn(conn_id)

    def next_write_index(self, conn_id):
        self.proxy_write_queues_index[conn_id] += 1
        if self.proxy_write_queues_index[conn_id] == 1000:
            self.proxy_write_queues_index[conn_id] = 100

#! /usr/bin/env python

import logging
import argparse
import json
from Crypto.PublicKey import RSA
from hashlib import sha1
from twisted.internet import reactor
from twisted.internet.error import CannotListenError
from twisted.web.http import HTTPFactory
from twisted_connect_proxy.server import ConnectProxy

from coordinator import Coordinator


def start_proxy(port):
    """Start the internal HTTP proxy server.

    The proxy, which runs locally, serves as a middleware,
    i.e. the client handler forwards clients' requests to the proxy,
    and the proxy is reponsible for communicating with the target server.

    It is suggested that an external HTTP proxy is specified
    in place of the internal one,
    for performance and stability considerations.
    See command line arguments for detailed information.
    """
    factory = HTTPFactory()
    factory.protocol = ConnectProxy
    reactor.listenTCP(port, factory, interface="127.0.0.1")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start ArkC server.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show detailed logs")
    parser.add_argument("-vv", action="store_true", dest="vv",
                        help="show debug logs")
    parser.add_argument('-c', '--config', dest="config", default='config.json',
                        help="You must specify a configuration files. \
                        By default ./config.json is used.")

    parser.add_argument('-ep', "--use-external-proxy", action="store_true",
                        help="use an external HTTPS proxy server running locally,\
                        e.g. polipo, for better performance.\
                        Fall back to in-built python proxy server otherwise.")

    args = parser.parse_args()

    data = {}

    # Load json configuration file
    try:
        data_file = open(args.config)
        data = json.load(data_file)
        data_file.close()
    except Exception as err:
        logging.error("Fatal error while loading configuration file.\n" +
                      str(err))
        quit()

    try:
        with open(data["central_cert"], "r") as f:
            remote_cert_txt = f.read()
            remote_cert = RSA.importKey(remote_cert_txt)
    except Exception as err:
        print ("Fatal error while loading client certificate.")
        print (err)
        quit()

    try:
        with open(data["local_cert_path"], "r") as f:
            local_cert = RSA.importKey(f.read())
        if not local_cert.has_private():
            print("Fatal error, no private key included in local certificate.")
    except IOError as err:
        print ("Fatal error while loading local certificate.")
        print (err)
        quit()

    if args.verbose:
        logging.basicConfig(level=logging.INFO)

    if args.vv:
        logging.basicConfig(level=logging.DEBUG)

    if not args.use_external_proxy:
        if "proxy_port" not in data:
            data["proxy_port"] = 8100
        start_proxy(data["proxy_port"])
    else:
        if "proxy_port" not in data:
            data["proxy_port"] = 8123

    if "udp_port" not in data:
        data["udp_port"] = 53

    if "delegated_domain" not in data:
        data["delegated_domain"] = "testing.arkc.org"

    if "self_domain" not in data:
        data["self_domain"] = "freedom.arkc.org"

    if "obfs4_exec" not in data:
        data["obfs4_exec"] = "obfs4proxy"

    if "obfs_level" not in data:
        data["obfs_level"] = 0

    # Start the loop
    try:
        reactor.listenUDP(
            data["udp_port"],
            Coordinator(
                data["proxy_port"],
                None,
                local_cert,
                remote_cert,
                data["delegated_domain"],
                data["self_domain"],
                data["obfs4_exec"],
                data["obfs_level"]
            )
        )
    except CannotListenError as err:
        print(err.socketError)
        if data["udp_port"] <= 1024 and str(err.socketError) == "[Errno 13] \
                Permission denied":
            print("root privilege may be required to listen to low ports")
        exit()

    reactor.run()

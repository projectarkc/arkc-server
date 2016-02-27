#! /usr/bin/env python

import logging
import argparse
import json
import sys
import os
import stat
import urllib

sys.path.insert(0, os.path.dirname(__file__))

from Crypto.PublicKey import RSA
from hashlib import sha1
from twisted.internet import reactor
from twisted.internet.error import CannotListenError
from twisted.web.http import HTTPFactory
from twisted_connect_proxy.server import ConnectProxy

from coordinator import Coordinator
from utils import generate_RSA, certstorage

VERSION = "0.2.1"


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


def main():
    parser = argparse.ArgumentParser(description=None)
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show detailed logs")
    parser.add_argument("-vv", action="store_true", dest="vv",
                        help="show debug logs")
    parser.add_argument(
        "--version", dest="version", action="store_true", help="show version number")
    parser.add_argument('-kg', '--keygen', dest="kg", action="store_true",
                        help="Generate a key string and quit, overriding other options")
    parser.add_argument('--get-meek', dest="dlmeek", action="store_true",
                        help="Download meek to home directory, overriding normal options")
    parser.add_argument('-c', '--config', dest="config", default=None,
                        help="specify a configuration files, required for ArkC to start")
    parser.add_argument("-t", action="store_true", dest="transmit",
                        help="use transmit server")

    parser.add_argument('-ep', "--use-external-proxy", action="store_true",
                        help="""use an external proxy server or handler running locally,e.g. polipo, for better performance.
Use this option to support other types of proxy other than HTTP, or use authentication at client-end proxy.
Fall back to in-built python proxy server otherwise.""")
    print(
        """ArkC Server V0.2, by ArkC Technology.
The programs is distributed under GNU General Public License Version 2.
""")

    args = parser.parse_args()
    if args.version:
        print("ArkC Server Version " + VERSION)
        sys.exit()
    elif args.kg:
        print("Generating 2048 bit RSA key.")
        print("Writing to home directory " + os.path.expanduser('~'))
        generate_RSA(os.path.expanduser(
            '~') + os.sep + 'arkc_pri.asc', os.path.expanduser('~') + os.sep + 'arkc_pub.asc')
        print(
            "Please save the above settings to client and server side config files.")
        sys.exit()
    elif args.dlmeek:
        if sys.platform == 'linux2':
            link = "https://github.com/projectarkc/meek/releases/download/v0.2/meek-client"
            localfile = os.path.expanduser('~') + os.sep + "meek-client"
        elif sys.platform == 'win32':
            link = "https://github.com/projectarkc/meek/releases/download/v0.2/meek-client.exe"
            localfile = os.path.expanduser('~') + os.sep + "meek-client.exe"
        else:
            print(
                "MEEK for ArkC has no compiled executable for your OS platform. Please compile and install from source.")
            print(
                "Get source at https://github.com/projectarkc/meek/tree/master/meek-client")
            sys.exit()
        print(
            "Downloading meek plugin (meek-client) from github to " + localfile)
        urllib.urlretrieve(link, localfile)
        if sys.platform == 'linux2':
            st = os.stat(localfile)
            os.chmod(localfile, st.st_mode | stat.S_IEXEC)
            print("File made executable.")
        print("Finished. If no error, you may change obfs_level and update pt_exec to " +
              localfile + " to use meek.")
        sys.exit()
    elif args.config is None:
        logging.fatal("Config file (-c or --config) must be specified.\n")
        parser.print_help()
        sys.exit()

    # mapping client public sha1 --> (RSA key object, client private sha1)
    certs = dict()

    data = {}

    # Load json configuration file
    try:
        data_file = open(args.config)
        data = json.load(data_file)
        data_file.close()
    except Exception as err:
        logging.error("Fatal error while loading configuration file.")
        print(err)  # TODO: improve error processing
        sys.exit()

    try:
        for client in data["clients"]:
            with open(client[0], "r") as f:
                remote_cert_txt = f.read()
                remote_cert = RSA.importKey(remote_cert_txt)
                remote_cert_txt = remote_cert_txt.strip(
                    ' ').lstrip('\n')
                certs[sha1(remote_cert_txt).hexdigest()] =\
                     [remote_cert, client[1]]
    except KeyError:
        pass
    except Exception as err:
        print ("Fatal error while loading client certificate.")
        print (err)
        sys.exit()

    try:
        certsdbpath = data["clients_db"]
    except KeyError:
        certsdbpath = None

    try:
        certs_db = certstorage(certs, certsdbpath)
    except Exception as err:
        print ("Fatal error while loading clients' certificate.")
        print (err)
        sys.exit()

    if args.transmit:
        try:
            with open(data["central_cert"], "r") as f:
                central_cert_txt = f.read()
                central_cert = RSA.importKey(central_cert_txt)
        except Exception as err:
            print ("Fatal error while loading client certificate.")
            print (err)
            sys.exit()
    else:
        central_cert = None

    try:
        with open(data["local_cert_path"], "r") as f:
            local_cert = RSA.importKey(f.read())
        if not local_cert.has_private():
            print("Fatal error, no private key included in local certificate.")
    except IOError as err:
        print ("Fatal error while loading local certificate.")
        print (err)
        sys.exit()

    if args.vv:
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG,
                            format="%(levelname)s: %(asctime)s; %(message)s")
    elif args.verbose:
        logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                            format="%(levelname)s: %(asctime)s; %(message)s")
    else:
        logging.basicConfig(stream=sys.stdout, level=logging.WARNING,
                            format="%(levelname)s: %(asctime)s; %(message)s")

    if not args.use_external_proxy:
        if "proxy_port" not in data:
            data["proxy_port"] = 8100
        start_proxy(data["proxy_port"])
    else:
        if "proxy_port" not in data:
            data["proxy_port"] = 8123

    if "udp_port" not in data:
        if args.transmit:
            data["udp_port"] = 8000
        else:
            data["udp_port"] = 53

    if "socks_proxy" not in data:
        data["socks_proxy"] = None

    if "delegated_domain" not in data:
        data["delegated_domain"] = "testing.arkc.org"

    if "self_domain" not in data:
        data["self_domain"] = "freedom.arkc.org"

    if "pt_exec" not in data:
        data["pt_exec"] = "obfs4proxy"

    if "obfs_level" not in data:
        data["obfs_level"] = 0
    elif 1 <= int(data["obfs_level"]) <= 2:
        logging.error(
            "Support for obfs4proxy is experimental with known bugs. Run this mode at your own risk.")

    if "meek_url" not in data:
        data["meek_url"] = "https://arkc-reflect1.appspot.com/"

    # Start the loop
    try:
        reactor.listenUDP(
            data["udp_port"],
            Coordinator(
                data["proxy_port"],
                data["socks_proxy"],
                local_cert,
                certs_db,
                central_cert,
                data["delegated_domain"],
                data["self_domain"],
                data["pt_exec"],
                data["obfs_level"],
                data["meek_url"],
                args.transmit
            )
        )
    except CannotListenError as err:
        print(err.socketError)
        if data["udp_port"] <= 1024 and str(err.socketError) == "[Errno 13] \
                Permission denied":
            print("root privilege may be required to listen to low ports")
        exit()

    try:
        reactor.run()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()

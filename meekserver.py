"""The MIT License (MIT)

Copyright (c) 2015 Dingyuan Wang

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import os
import time
import shlex
import select
import subprocess
import SocketServer
import threading
import logging
import tempfile
from utils import socksocket, GeneralProxyError, ProxyConnectionError, ProxyError, PROXY_TYPES

try:
    DEVNULL = subprocess.DEVNULL
except AttributeError:
    # Python 3.2
    DEVNULL = open(os.devnull, 'wb')

logtime = lambda: time.strftime('%Y-%m-%d %H:%M:%S')


class PTConnectFailed(Exception):
    pass


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True


# TODO: should it be deleted?
class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):

    # def __init__(self, initiator):
    #    self.initiator=initiator

    def handle(self):
        ptsock = socksocket()
        ptsock.set_proxy(*CFG['_ptcli'])
        host, port = CFG['server'].rsplit(':', 1)
        try:
            ptsock.connect((host, int(port)))
            run = 1
            while run:
                rl, wl, xl = select.select([self.request, ptsock], [], [], 300)
                if not rl:
                    break
                run = 0
                for s in rl:
                    try:
                        data = s.recv(1024)
                    except Exception as ex:
                        print(logtime(), ex)
                        continue
                    if data:
                        run += 1
                    else:
                        continue
                    if s is self.request:
                        ptsock.sendall(data)
                    elif s is ptsock:
                        self.request.sendall(data)
        except GeneralProxyError as ex:
            logging.warning(
                logtime() + 'Proxy Error. Please check the config and the log of PT.')
            self.request.close()
        except SOCKS4Error as ex:
            #logging.info(logtime() + 'SOCKS4 Error in PTproxy.')
            self.request.close()
        except ProxyConnectionError as ex:
            logging.info(logtime() + 'Connection failed.')
            self.request.close()

CFG = {
    "role": "client",
    "state": tempfile.gettempdir(),
    "local": "127.0.0.1:" + str(localport),
    "ptname": "meek",
    "ptserveropt": "",
    "ptargs": ""
}

CFG["server"] = remoteaddress + ":" + str(remoteport)
CFG["ptproxy"] = ""
CFG["ptexec"] = ptexec

TRANSPORT_VERSIONS = ('1',)

startupinfo = None
if os.name == 'nt':
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW


def ptenv():
    env = os.environ.copy()
    env['TOR_PT_STATE_LOCATION'] = CFG['state']
    env['TOR_PT_MANAGED_TRANSPORT_VER'] = ','.join(TRANSPORT_VERSIONS)
    if CFG["role"] == "client":
        env['TOR_PT_CLIENT_TRANSPORTS'] = CFG['ptname']
        if CFG.get('ptproxy'):
            env['TOR_PT_PROXY'] = CFG['ptproxy']
    elif CFG["role"] == "server":
        env['TOR_PT_SERVER_TRANSPORTS'] = CFG['ptname']
        env['TOR_PT_SERVER_BINDADDR'] = '%s-%s' % (
            CFG['ptname'], CFG['server'])
        env['TOR_PT_ORPORT'] = CFG['local']
        env['TOR_PT_EXTENDED_SERVER_PORT'] = ''
        if CFG.get('ptserveropt'):
            env['TOR_PT_SERVER_TRANSPORT_OPTIONS'] = ';'.join(
                '%s:%s' % (CFG['ptname'], kv) for kv in CFG['ptserveropt'].split(';'))
    else:
        raise ValueError('"role" must be either "server" or "client"')
    return env


def checkproc():
    global PT_PROC
    if PT_PROC is None or PT_PROC.poll() is not None:
        PT_PROC = subprocess.Popen(shlex.split(
            CFG['ptexec']), bufsize=-1, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=DEVNULL, env=ptenv(), startupinfo=startupinfo)
    return PT_PROC


def parseptline(stdout):
    global CFG
    for ln in iter(stdout.readline, ''):
        ln = ln.decode('utf_8', errors='replace').rstrip('\n')
        sp = ln.split(' ', 1)
        kw = sp[0]
        if kw in ('ENV-ERROR', 'VERSION-ERROR', 'PROXY-ERROR',
                  'CMETHOD-ERROR', 'SMETHOD-ERROR'):
            raise PTConnectFailed(ln)
        elif kw == 'VERSION':
            if sp[1] not in TRANSPORT_VERSIONS:
                raise PTConnectFailed('PT returned invalid version: ' + sp[1])
        elif kw == 'PROXY':
            if sp[1] != 'DONE':
                raise PTConnectFailed('PT returned invalid info: ' + ln)
        elif kw == 'CMETHOD':
            vals = sp[1].split(' ')
            if vals[0] == CFG['ptname']:
                host, port = vals[2].split(':')
                CFG['_ptcli'] = (
                    PROXY_TYPES[vals[1].upper()], host, int(port),
                    True, CFG['ptargs'][:255], CFG['ptargs'][255:] or '\0')
                print('==============================')
        elif kw in ('CMETHODS', 'SMETHODS') and sp[1] == 'DONE':
            print(logtime(), 'PT started successfully.')
            LOCK.set()
            return
        else:
            # Some PTs may print extra debugging info
            print(logtime(), ln)


def runpt():
    global CFG, PTREADY
    while CFG['_run']:
        print(logtime(), 'Starting PT...')
        proc = checkproc()
        # If error then die
        parseptline(proc.stdout)
        PTREADY.set()
        # Use this to block
        # stdout may be a channel for logging
        try:
            out = proc.stdout.readline()
            while out:
                print(
                    logtime(), out.decode('utf_8', errors='replace').rstrip('\n'))
        except BrokenPipeError:
            pass
        PTREADY.clear()
        print(logtime(), 'PT died.')

PT_PROC = None
PTREADY = threading.Event()

try:
    CFG['_run'] = True
    if CFG['role'] == 'client':
        ptthr = threading.Thread(target=runpt)
        ptthr.daemon = True
        ptthr.start()
        PTREADY.wait()
        host, port = CFG['local'].split(':')
        # TODO: Don't need this TCP server, can handle it via txsocksx
        server = ThreadedTCPServer(
            (host, int(port)), ThreadedTCPRequestHandler)
        server.serve_forever()
    else:
        runpt()
finally:
    CFG['_run'] = False
    if PT_PROC:
        PT_PROC.kill()

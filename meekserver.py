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
from utils import socksocket, GeneralProxyError, ProxyConnectionError, PROXY_TYPES

try:
    DEVNULL = subprocess.DEVNULL
except AttributeError:
    # Python 3.2
    DEVNULL = open(os.devnull, 'wb')

logtime = lambda: time.strftime('%Y-%m-%d %H:%M:%S')


class PTConnectFailed(Exception):
    pass


CFG = {
    "role": "client",
    "state": tempfile.gettempdir(),
    "local": "127.0.0.1:" + str(localport),
    "ptname": "meek",
    "ptserveropt": "",
    "ptargs": ""
}
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
                localport = port
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
    runpt()
finally:
    CFG['_run'] = False
    if PT_PROC:
        PT_PROC.kill()

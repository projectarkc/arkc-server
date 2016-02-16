import os
import time
import shlex
import subprocess
import threading
import tempfile

try:
    DEVNULL = subprocess.DEVNULL
except AttributeError:
    # Python 3.2
    DEVNULL = open(os.devnull, 'wb')

logtime = lambda: time.strftime('%Y-%m-%d %H:%M:%S')


class PTConnectFailed(Exception):
    pass

CFG = dict()
LOCK = None
PT_PROC = None
PTREADY = threading.Event()
initator = None

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
    global CFG, init
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
                initiator.ptproxy_local_port = int(port)
                print('==============================')
        elif kw in ('CMETHODS', 'SMETHODS') and sp[1] == 'DONE':
            print(logtime(), 'PT started successfully.')
            initiator.check.set()
            return
        else:
            # Some PTs may print extra debugging info
            print(logtime(), ln)


def runpt():
    global CFG, PTREADY
    if CFG['_run']:
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
        except OSError:
            pass
        PTREADY.clear()
        print(logtime(), 'PT died.')


def meekinit(init, var):
    global CFG, LOCK, initiator
    CFG = {
        "role": "client",
        "state": tempfile.gettempdir(),
        "ptname": "meek",
        "ptserveropt": "",
        "ptargs": "",
        "ptproxy": "",
        "ptexec": var['ptexec']
    }
    initiator = init

    try:
        CFG['_run'] = True
        runpt()
    finally:
        CFG['_run'] = False
        if PT_PROC:
            PT_PROC.kill()


def meekterm():
    CFG['_run'] = False
    PT_PROC.kill()

#!/usr/bin/env python
# coding:utf-8

import os
import time
import shlex
import subprocess
import tempfile
import logging


class PTConnectFailed(Exception):
    pass


class meek():
    try:
        DEVNULL = subprocess.DEVNULL
    except AttributeError:
        # Python 3.2
        DEVNULL = open(os.devnull, 'wb')

    startupinfo = None
    if os.name == 'nt':
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    TRANSPORT_VERSIONS = ('1',)

    def __init__(self, initiator, var):
        self.CFG = {
            "role": "client",
                    "state": tempfile.gettempdir(),
                    "ptname": "meek",
                    "ptserveropt": "",
                    "ptargs": "",
                    "ptproxy": "",
                    "ptexec": var['ptexec']
        }
        self.LOCK = None
        self.PT_PROC = None
        self.initiator = initiator

    def logtime(self):
        return time.strftime('%Y-%m-%d %H:%M:%S')

    def ptenv(self):
        env = os.environ.copy()
        env['TOR_PT_STATE_LOCATION'] = self.CFG['state']
        env['TOR_PT_MANAGED_TRANSPORT_VER'] = ','.join(self.TRANSPORT_VERSIONS)
        if self.CFG["role"] == "client":
            env['TOR_PT_CLIENT_TRANSPORTS'] = self.CFG['ptname']
            if self.CFG.get('ptproxy'):
                env['TOR_PT_PROXY'] = self.CFG['ptproxy']
        else:
            raise ValueError('"role" must be either "server" or "client"')
        return env

    def checkproc(self):
        if self.PT_PROC is None or self.PT_PROC.poll() is not None:
            self.PT_PROC = subprocess.Popen(shlex.split(self.CFG['ptexec']),
                                            bufsize=-1, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=self.DEVNULL, env=self.ptenv(),
                                            startupinfo=self.startupinfo)

    def parseptline(self, stdout):
        for ln in iter(stdout.readline, ''):
            ln = ln.decode('utf_8', errors='replace').rstrip('\n')
            sp = ln.split(' ', 1)
            kw = sp[0]
            if kw in ('ENV-ERROR', 'VERSION-ERROR', 'PROXY-ERROR',
                      'CMETHOD-ERROR', 'SMETHOD-ERROR'):
                raise PTConnectFailed(ln)
            elif kw == 'VERSION':
                if sp[1] not in self.TRANSPORT_VERSIONS:
                    raise PTConnectFailed(
                        'PT returned invalid version: ' + sp[1])
            elif kw == 'PROXY':
                if sp[1] != 'DONE':
                    raise PTConnectFailed('PT returned invalid info: ' + ln)
            elif kw == 'CMETHOD':
                vals = sp[1].split(' ')
                if vals[0] == self.CFG['ptname']:
                    host, port = vals[2].split(':')
                    self.initiator.ptproxy_local_port = int(port)
                    print('==============================')
            elif kw in ('CMETHODS', 'SMETHODS') and sp[1] == 'DONE':
                print(self.logtime(), 'PT started successfully.')
                self.initiator.check.set()
                return
            else:
                # Some PTs may print extra debugging info
                print(self.logtime(), ln)

    def runpt(self):
        if self.CFG['_run']:
            print(self.logtime(), 'Starting PT...')
            self.checkproc()
            # If error then die
            self.parseptline(self.PT_PROC.stdout)
            # Use this to block
            # stdout may be a channel for logging
            try:
                out = self.PT_PROC.stdout.readline()
                while out:
                    print(
                        self.logtime(), out.decode('utf_8', errors='replace').rstrip('\n'))
            except OSError as err:
                print(err)
            print(self.logtime(), 'PT died.')

    def meekinit(self):
        try:
            self.CFG['_run'] = True
            self.runpt()
        except Exception:
            logging.debug("Error occurred in MEEK thread.")
        finally:
            self.CFG['_run'] = False
            if self.PT_PROC:
                try:
                    self.PT_PROC.kill()
                    self.PT_PROC.wait()
                except Exception:
                    pass
            return

    def meekterm(self):
        self.CFG['_run'] = False
        try:
            self.PT_PROC.kill()
            self.PT_PROC.wait()
        except Exception:
            pass

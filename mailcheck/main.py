#! /usr/bin/env python3

import poplib
import time
from email import policy
from email.parser import BytesParser

MAILADDR = "service@arkc.org"
PASSWD = "freedom.arkc.org"


def parse(body):
    msg = BytesParser(policy=policy.default).parsebytes(b'\n'.join(body))
    if "Conference Registration" in msg['subject']:
        sha1 = msg.get_body(preferencelist=("plain")).get_content()
        sha1 = sha1.split('\n')[0]
        for part in msg.get_body().iter_attachments():
            pubkey = part.get_content()
            return sha1, pubkey
while True:
    M = poplib.POP3_SSL('pop.zoho.com')
    M.user(MAILADDR)
    res = M.pass_(PASSWD)
    if b"OK" in res:
        numMessages = M.stat()[0]
        number = 1
        while number < numMessages + 1:
            (server_msg, body, octets) = M.retr(number)
            sha1, pubkey = parse(body)
            M.dele(number)
            number += 1
    M.quit()
    time.sleep(30)

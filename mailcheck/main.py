#! /usr/bin/env python3

import poplib
import time
from email import policy
from email.parser import BytesParser
import sqlite3
from common import certloader

MAILADDR = "service@arkc.org"
PASSWD = "freedom.arkc.org"


def parse(body):
    msg = BytesParser(policy=policy.default).parsebytes(b'\n'.join(body))
    if 'multipart' in msg['content-type'] and "Conference Registration" in msg['subject']:
        sha1 = msg.get_body(preferencelist=("plain")).get_content()
        sha1 = sha1.split('\n')[0]
        for part in msg.iter_attachments():
            pubkey = part.get_content()
            return sha1, pubkey
    return None, None

while True:
    M = poplib.POP3_SSL('pop.zoho.com')
    M.user(MAILADDR)
    res = M.pass_(PASSWD)
    if b"OK" in res:
        con = sqlite3.connect('database.db')
        cur = con.cursor()
        numMessages = M.stat()[0]
        number = 1
        while number < numMessages + 1:
            (server_msg, body, octets) = M.retr(number)
            pri_sha1, pubkey = parse(body)
            pub_sha1 = certloader(pubkey).getSHA1()
            cur.execute(
                'insert into test certs(?,?,?)', (pub_sha1, pri_sha1, pubkey))
            M.dele(number)
            number += 1
        con.commit()
        con.close()
    M.quit()
    time.sleep(30)

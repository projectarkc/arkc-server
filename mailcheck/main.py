#! /usr/bin/env python3
# coding:utf-8

import sys
import argparse
import smtpd
import asyncore
from email.parser import Parser
import sqlite3
import logging
from common import certloader


class CorruptMail(Exception):
    pass


class SMTPserver(smtpd.SMTPServer):

    def process_message(self, peer, mailfrom, rcpttos, data):
        try:
            print(data)
            pri_sha1, pubkey = parse(body)
            pub_sha1 = certloader(pubkey).getSHA1()
            cur.execute(
                'INSERT INTO certs VALUES (?,?,?)', (pub_sha1, pri_sha1, pubkey))
            con.commit()
            logging.info("Add client with public sha1 " + pub_sha1)
        except CorruptMail:
            logging.warning("Deleting a malformed email.")
        except Exception:
            logging.warning("Error processing one email.")


def parse(body):
    msg = Parser.parsestr(body)
    if 'multipart' in msg['content-type'] and "Conference Registration" in msg['subject']:
        sha1 = msg.get_body(preferencelist=("plain")).get_content()
        sha1 = sha1.split('\n')[0]
        for part in msg.iter_attachments():
            pubkey = part.get_content()
            return sha1, pubkey
    raise CorruptMail
    return None, None


def main():
    parser = argparse.ArgumentParser(description=None)
    # parser.add_argument(
    #    "--version", dest="version", action="store_true", help="show version number")
    parser.add_argument('-db', '--database', dest="db_path", required=True,
                        help="specify the database file to use")
    args = parser.parse_args()

    logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                        format="%(levelname)s: %(asctime)s; %(message)s")

    dbpath = args.db_path

    try:
        con = sqlite3.connect(dbpath)
    except Exception as err:
        logging.error("Error when loading database file.")
        print(err)
        sys.exit()

    cur = con.cursor()
    cur.execute(
        "CREATE TABLE certs (pubkey_sha1 text, prikey_sha1, text, pubkey_body text)")
    con.commit()

    smtp = SMTPserver(('', 25), None)

    try:
        asyncore.loop(use_poll=True)
    except KeyboardInterrupt:
        pass
    finally:
        con.close()

if __name__ == "__main__":
    main()

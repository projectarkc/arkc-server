#! /usr/bin/env python3

import poplib
import argparse
import time
from email import policy
from email.parser import BytesParser
import sqlite3
import logging
from common import certloader

class CorruptMail(Exception):
    pass

def parse(body):
    msg = BytesParser(policy=policy.default).parsebytes(b'\n'.join(body))
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
    parser.add_argument('-c', '--config', dest="config", required=True,
                        help="specify a configuration files, required to start")
    args = parser.parse_args()

    logging.basicConfig(stream=sys.stdout, level=logging.INFO,
                        format="%(levelname)s: %(asctime)s; %(message)s")

    # Load json configuration file
    try:
        data_file = open(args.config)
        data = json.load(data_file)
        data_file.close()
    except Exception as err:
        logging.error("Format error while loading configuration file.")
        print(err)  # TODO: improve error processing
        sys.exit()

    try:
        dbpath = data["db_path"]
        user = data["user"]
        passwd = data["password"]
        ssl = data["ssl"]
        popserver = data["mail_server"]
        if "mail_port" in data:
            port = data["mail_server"]
        elif ssl:
            port = poplib.POP3_SSL_PORT
        else:
            port = poplib.POP3_PORT
    except Exception as err:
        logging.error("Broken configuration file.")
        print(err)
        sys.exit()

    try:
        con = sqlite3.connect(dbpath)
    except Exception as err:
        logging.error("Error when loading database file.")
        print(err)
        sys.exit()

    cur = con.cursor()
    cur.execute("CREATE TABLE certs IF NOT EXISTS (pubkey_sha1 text, prikey_sha1, text, pubkey_body text)")
    con.commit()

    while True:
        if ssl:
            M = poplib.POP3_SSL(popserver, port)
        else:
            M = poplib.POP3(popserver, port)
        M.user(user)
        res = M.pass_(passwd)
        if b"OK" in res:
            numMessages = M.stat()[0]
            number = 1
            while number < numMessages + 1:
                (server_msg, body, octets) = M.retr(number)
                try:
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
                finally:
                    M.dele(number)
                    number += 1
                
        M.quit()
        time.sleep(30)
    con.close()

if __name__ == "__main__":
    main()

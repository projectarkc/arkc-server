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


cur = None
con = None


class CorruptMail(Exception):
    pass


class SMTPserver(smtpd.SMTPServer):


    def process_message(self, peer, mailfrom, rcpttos, data):
        global cur, con
        try:
            pri_sha1, pubkey = parse(data)
            pub_sha1 = certloader(pubkey).getSHA1()
            cur.execute(
                'INSERT INTO certs VALUES (?,?,?)', (pub_sha1, pri_sha1, pubkey))
            con.commit()
            logging.info("Adding client with public sha1 " + pub_sha1)
        except CorruptMail:
            logging.warning("Ignoring a malformed email.")
        except Exception:
            logging.warning("Error processing an email.")


def parse(body):
    p = Parser()
    msg = p.parsestr(body)
    if "Conference Registration" not in msg['Subject'] or not msg.is_multipart():
        raise CorruptMail
    attachments = []
    body_text = b""
    body_html = b""
    for part in msg.walk():
        attachment = email_parse_attachment(part)
        if attachment:
            attachments.append(attachment)
        elif part.get_content_type() == "text/plain":
            body_text += part.get_payload(decode=True)
            sha1 =  body_text.split(b'\n')[0]
        #elif part.get_content_type() == "text/html":
        #    body_html += unicode(part.get_payload(decode=True),
        #                         part.get_content_charset(), 'replace').encode('utf8', 'replace')
    if len(attachments) == 0 or len(sha1) != 40:
        raise CorruptMail
    return sha1.decode('UTF-8'), attachments[0]['filedata'].decode('UTF-8')


def email_parse_attachment(message_part):

    content_disposition = message_part.get("Content-Disposition", None)
    if content_disposition:
        dispositions = content_disposition.strip().split(";")
        if bool(content_disposition and dispositions[0].lower() == "attachment"):
            attachment = {
                'filedata': message_part.get_payload(decode = True),
                'content_type': message_part.get_content_type(),
                'filename': "default"
            }
            for param in dispositions[1:]:
                name, value = param.split("=")
                name = name.strip().lower()

                if name == "filename":
                    attachment['filename'] = value.replace('"', '')

            return attachment

    return None


def main():
    global cur, con
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
    try:
        cur.execute(
        "CREATE TABLE certs (pubkey_sha1 text, prikey_sha1 text, pubkey_body text)")
        con.commit()
    except sqlite3.OperationalError:
        pass

    smtp = SMTPserver(('', 25), None)

    try:
        asyncore.loop(use_poll=True)
    except KeyboardInterrupt:
        pass
    finally:
        con.close()

if __name__ == "__main__":
    main()

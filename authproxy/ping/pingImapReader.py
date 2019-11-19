#!/usr/bin/env python
"""Get the ping OTP token from email.

Optionally poll mailbox in case mail has not yet arrived."""

import imaplib
import os
import os.path as osp
import re
import sys
from time import sleep


TOKEN_MATCH_RE = r'<p style="font-size:26px;line-height:1em;font-weight:500;padding:45px 0 55px 0;margin:0;text-align:center">\s*(\d+)\s*</p>'


class NoToken(Exception):
    """No new Ping token found in mailbox"""


class PingImapReader(object):
    """An IMAP client that reads ping OTP token mails from an IMAP inbox"""

    def __init__(self, imapServer, imapPort, imapUser, imapPassword, logger):
        self.log = logger
        self.imapServer = imapServer
        self.imapPort = imapPort
        self.imapUser = imapUser
        self.imapPassword = imapPassword

    def getToken(self, client):
        """Try to fetch the PING token, raise exception if not available"""
        self.log.debug("Attempting to fetch ping token")
        # Should probably also filter by date but should be OK for most part
        status, data = client.search(None, 'UNSEEN FROM "noreply@pingidentity.com"')
        self.log.debug('Got data:%s', data)
        mailSeqnums = data[0].decode().split()
        if not mailSeqnums:
            raise NoToken
        lastMail = mailSeqnums[-1]
        self.log.debug('lastMail:%s', lastMail)
        # BODY[1] is the text/plain part of the body without multipart headers.
        # See RFC2060
        typ, results = client.fetch(lastMail, "(BODY[1])")
        self.log.debug('got results:%s', results)
        # elements of results are either plain strings (status values) or tuples
        # (message body and other info)
        for elem in results:
            if isinstance(elem, tuple):
                contents = elem[1].decode()  # 0 is the tag
        self.log.debug('Got contents:%s', contents)
        matches = re.search(TOKEN_MATCH_RE, contents, re.DOTALL)
        self.log.debug('Found matches:%s', matches.groups())
        return matches.group(1)

    def getOtpEmail(self, maxAttempts=15):
        """Fetch the latest email that contains the PING OTP token"""
        with imaplib.IMAP4_SSL(self.imapServer, self.imapPort) as client:
            client.login(self.imapUser, self.imapPassword)
            client.select()
            attempts = maxAttempts
            while attempts > 0:
                try:
                    return self.getToken(client)
                except NoToken:
                    self.log.warning("No unread token found in mailbox")
                    pass
                sleep(2)
                attempts -= 1
            else:
                self.log.error("No unread ping token found in inbox after %s attempts",
                          maxAttempts)
                raise NoToken

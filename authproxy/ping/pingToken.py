"""Not a real auth proxy but just an endpoint to get the ping OTP token (for other apps)"""


class PingTokenGetter(object):
    def __init__(self, globalConfig, logger):
        self.log = logger
        self.debug = self.log.debug
        self.error = self.log.error
        libConfig = config['ping']
        self.pingUsername = libConfig['ping_username']
        self.pingPassword = libConfig['ping_password']
        self.imapUsername = libConfig['imap_username']
        self.imapPassword = libConfig['imap_password']
        self.imapServer = libConfig['imap_server']
        self.imapPort = libConfig['imap_port']
        self.imapClient = PingImapReader(self.imapServer,
                                         self.imapPort,
                                         self.imapUsername,
                                         self.imapPassword,
                                         self.log)

    def getToken():
        return imapClient.getOtpEmail()

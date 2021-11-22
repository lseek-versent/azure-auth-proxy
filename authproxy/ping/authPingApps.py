"""Authenticate an app in the Versent PingID portal with PingID.

This script is expected to be run as part of the bigger "auth proxy"
application.
"""
import base64
from datetime import datetime, timezone
from functools import lru_cache

from bs4 import BeautifulSoup

from ..authClient import ServiceProxy
from .pingSaml import PingSamlClient


class PingApp(ServiceProxy):
    """Log into a PingID app on the Versent desktop portal using the ping SAML
    client to do the SAML dance"""

    # Subclasses MUST override this
    PARTNER_SP_ID = ""

    def __init__(self, globalConfig, logger):
        """Parameters:

            config:
                The (global) python config dictionary
            logger:
                The instance of logger to use for logging"""
        self.log = logger
        self.debug = self.log.debug
        self.error = self.log.error

        self.globalConfig = globalConfig

    def getSAMLResponse(self):
        self.log.debug("Getting SAML response")
        appUrl = f'https://id.versent.com.au/idp/startSSO.ping?PartnerSpId={self.PARTNER_SP_ID}'
        samlClient = PingSamlClient(self.globalConfig, appUrl, self.log)
        response, expiry = samlClient.submitSamlRequest(wholeResponse=True)
        return (samlClient, response, expiry)

    def doAuth(self, forConsole=True):
        samlClient, response, expiry = self.getSAMLResponse()
        self.log.debug('Got response, expires on:%s', expiry)
        now = datetime.now(tz=timezone.utc)
        if now >= expiry:
            self.log.debug('Invalidating cached SAML response')
            self.getSAMLResponse.cache_clear()
            samlClient, response, _ = self.getSAMLResponse()
        else:
            self.log.debug('Using cached/new SAMLResponse')
        if not forConsole:
            response = samlClient.extractSamlResponse(response)
        self.log.debug('Returning SAMLResponse:%s', response)
        headers = {
            'Content-Type': 'text/html' if forConsole else 'text/plain',
            'Origin': 'https://id.versent.com.au',
            'Referer': 'https://id.versent.com.au',
        }
        return (headers, response)


class BoxClient(PingApp):
    """Box account"""

    PARTNER_SP_ID = 'box.net'


class LucidChartClient(PingApp):
    PARTNER_SP_ID = 'lucidchart.com'

"""Authenticate Box account with PingID.

This script is expected to be run as part of the bigger "auth proxy"
application.

The configuration options for this module should reside in the 'ping_box'
sub-dictionary of the global configuration dictionary. The following
configuration keys are understood and will be processed:

    {
        'ping_box': {
            'start_sso_url': 'https://url.to.box/from/ping',
        }
    }

    where:
        start_sso_url:
            The URL to PingID that returns the SAML request and relay state.
"""
import base64
from datetime import datetime, timezone
from functools import lru_cache

from bs4 import BeautifulSoup

from ..authClient import ServiceProxy
from .pingSaml import PingSamlClient


class BoxClient(ServiceProxy):
    """Log into a Box account using the SAML client to do the SAML dance"""

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
        boxUrl = 'https://id.versent.com.au/idp/startSSO.ping?PartnerSpId=box.net'
        samlClient = PingSamlClient(self.globalConfig, boxUrl, self.log)
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
        }
        return (headers, response)

"""Script to use the Azure SAML library to authenticate for the GlobalProtect
VPN

This script is expected to be run as part of the bigger "auth proxy"
application.

The configuration options for this module should reside in the 'azure_globalprotect'
sub-dictionary of the global configuration dictionary. The following
configuration keys are understood and will be processed:

    {
        'azure_globalprotect': {
            'server_url': "..."
        }
    }

    where:
        server_url:
            (Base) URL of the VPN server to contact. Globalprotect service
            endpoints will be constructed by appending them to this URL.
"""


import base64
from datetime import datetime, timezone
from functools import lru_cache
import json
import os
import re
import urllib.parse
from xml.etree import ElementTree

import requests

from ..authClient import ServiceProxy
from .azureSaml import AzureSamlClient


class GlobalProtectClient(ServiceProxy):
    CONFIG_KEY = 'azure_globalprotect'

    def __init__(self, globalConfig, logger):
        """Parameters:

            globalConfig:
                The (global) python config dictionary
            logger:
                The instance of logging.Logger to use for logging"""
        self.log = logger
        self.debug = self.log.debug
        self.error = self.log.error

        self.globalConfig = globalConfig
        config = globalConfig[self.CONFIG_KEY]
        self.serverUrl = config['server_url']

    def post(self, endpoint, formDict):
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'PAN GlobalProtect/4.1.3-8 (Apple Mac OS X 10.14.0)'
        }
        url = '{}/{}'.format(self.serverUrl, endpoint)
        self.debug('POSTing to:%s', url)
        resp = requests.post(url, headers=headers, data=formDict, verify=False)
        self.debug('Got response:"""%s"""', resp.text)
        resp.raise_for_status()
        return resp

    def getSamlRequest(self):
        """Get the SAML request to make"""
        preloginForm = {
            'tmp': 'tmp',
            'clientVer': 4100,
            'clientos': 'Mac',
            'os-version': 'Apple Mac OS X 10.14.0',
            'ipv6-support': 'yes'
        }
        resp = self.post('ssl-vpn/prelogin.esp', preloginForm)
        parsedXml = ElementTree.fromstring(resp.text)
        tree = ElementTree.ElementTree(parsedXml)
        root = tree.getroot()
        samlRequest = root.findall('saml-request')[0]
        samlRequestStr = base64.b64decode(samlRequest.text).decode()
        self.debug('Got SAML request:%s', samlRequestStr)
        return samlRequestStr

    def getRelayState(self, samlRequest):
        parts = urllib.parse.urlparse(samlRequest)
        qs = urllib.parse.parse_qs(parts.query)
        self.debug('Got relay_state:%s', qs['RelayState'])
        return qs['RelayState']

    # The SAML assertion for GlobalProtect has a validity of 60 mins. So if we
    # want to log reconnect within a 60 min interval we can reuse the assertion
    # without having to go through the entire SAML dance again.
    @lru_cache(maxsize=1)
    def getSAMLResponse(self):
        samlRequest = self.getSamlRequest()
        relayState = self.getRelayState(samlRequest)
        self.log.debug("Getting SAML response")
        samlClient = AzureSamlClient(self.globalConfig,
                                     samlRequest,
                                     self.log)
        response, expiry = samlClient.submitSamlRequest()
        preLoginCookie = self.getPreLoginCookie(response, relayState)
        return (preLoginCookie, expiry)

    def doAuth(self):
        response, expiry = self.getSAMLResponse()
        self.log.debug('Got response, expires on:%s', expiry)
        now = datetime.now(tz=timezone.utc)
        if now >= expiry:
            self.log.debug('Invalidating cached SAML response')
            self.getSAMLResponse.cache_clear()
            response, _ = self.getSAMLResponse()

        self.debug('Got cookie:%s', response)
        headers = {
            'Referer': 'https://login.microsoftonline.com/',
            'Content-Type': 'text/plain',
        }
        return (headers, response)

    def getPreLoginCookie(self, samlResponse, relayState):
        """Submit SAML response to VPN server and get pre-login cookie"""
        formDict = {
            "SAMLResponse": samlResponse,
            "RelayState": relayState
        }
        resp = self.post("SAML20/SP/ACS", formDict)
        self.debug("Got VPN response:%s", resp.text)
        preLoginCookie = None
        cookie_re = re.compile(r'<prelogin-cookie>([^<]+)</prelogin-cookie>')
        match = cookie_re.search(resp.text)
        if match:
            preLoginCookie = match.group(1)
        else:
            self.error('Could not find prelogin-cookie')
        self.debug('Got cookie:%s', preLoginCookie)
        return preLoginCookie

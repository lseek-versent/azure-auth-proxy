"""mitmproxy "addon" to intercept login auth requests to Azure for the
GlobalProtect VPN

This script is expected to be run inside a docker container containing all the
relevant packages. Also, the gpg agent musht be running with the password to
the password and totp secret files being read into the agent's memory (couldn't
get the azure saml library to start up the gpg agent and ask for credentials
within the script).
"""


import base64
import json
import os
import re
import urllib.parse
from xml.etree import ElementTree

from mitmproxy import http, ctx
import requests

from azuresaml import AzureSamlClient
from samllogger import SamlLogger


DEFAULT_VPN_AUTH_ENDPOINT = 'https://www.vpn.com/vpn'
CONFFILE_PATH = os.getenv('CONFFILE_PATH', '/azuresaml/config.json')
CONFIG_KEY = 'vpn_login_hook'
VPN_LOGGER_NAME = "vpnLoginHook"


class GlobalProtectClient(object):
    def __init__(self, globalConfig, logger):
        """Parameters:

            config:
                The (global) python config dictionary
            logger:
                The instance of SamlLogger to use for logging"""
        self.log = logger
        self.debug = self.log.debug
        self.error = self.log.error

        self.globalConfig = globalConfig
        config = globalConfig[CONFIG_KEY]
        self.serverUrl = config['server_url']
        self.enableDebugLogs = config['verbose']
        self.samlRequest = self.getSamlRequest()
        self.relayState = self.getRelayState(self.samlRequest)

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

    def doAuth(self):
        samlClient = AzureSamlClient(self.globalConfig, self.samlRequest, self.log)
        samlResponse = samlClient.submitSamlRequest()
        self.debug('Got samlResponse:%s', samlResponse)
        preLoginCookie = self.getPreLoginCookie(samlResponse)

        headers = {
            'Referer': 'https://login.microsoftonline.com/',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Content-Type': 'text/plain',
        }
        return http.HTTPResponse.make(
            200,
            preLoginCookie.encode(),
            headers)

    def getPreLoginCookie(self, samlResponse):
        """Submit SAML response to VPN server and get pre-login cookie"""
        formDict = {
            "SAMLResponse": samlResponse,
            "RelayState": self.relayState
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


class GlobalProtectVpnLoginHook(object):
    def __init__(self, customConfigFile):
        with open(customConfigFile) as conffile:
            self.globalConfig = json.load(conffile)
        self.config = self.globalConfig[CONFIG_KEY]
        self.hookEndpoint = self.config.get('vpn_auth_endpoint',
                                            DEFAULT_VPN_AUTH_ENDPOINT)
        self.verbose = self.config.get('verbose', False)
        self.logger = SamlLogger(ctx.log)
        self.logger.enableDebugLogs = self.verbose

    def request(self, flow):
        """mitmproxy hook to intercept requests"""
        if flow.request.url == self.hookEndpoint:
            ctx.log.info('Intercepted request to:{}'.format(self.hookEndpoint))
            samlClient = GlobalProtectClient(self.globalConfig, self.logger)
            flow.response = samlClient.doAuth()


addons = [GlobalProtectVpnLoginHook(CONFFILE_PATH)]

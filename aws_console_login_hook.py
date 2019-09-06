"""mitmproxy "addon" to intercept login auth requests to Azure for the AWS
console

This script is expected to be run inside a docker container containing all the
relevant packages. Also, the gpg agent musht be running with the password to
the password and totp secret files being read into the agent's memory (couldn't
get the azure saml library to start up the gpg agent and ask for credentials
within the script).

Lastly, because this is an mitmproxy addon we can't have command line arguments
(or rather I don't know how to do so yet). We therefore pass in required
arguments through environment variables that must be decared when starting up
the docker container.

The configuration for the console login hook is read from a JSON file with (at
least) the following keys:

    {
        "console_login_hook": {
            "tenant_id": "<aws_tenant_id>",
            "app_id": "<aws_app_id>"
            "console_auth_endpoint": "<endpoint to use for console auth [optional]>"
            "verbose": <true|false, default: false>,
        }
    }

Note that root of the config file is NOT the console login hook config but
instead the console login hook config resides in a section within the config.
This allows us to have one config file for all relevant modules.

Reading from a config file allows us to mount the config file from the host and
modify it on the fly without having to restart the docker container (which we
would have to do if we were using environment variables). The config file is
read each time the hook is run and therefore modifications are reflected on the
next request.

The path to the config file will be read from the CONFFILE_PATH environment
variable which should be passed in when the docker container starts.
"""


import base64
from datetime import datetime, timezone, timedelta
import json
import sys
import os
import urllib.parse
from uuid import uuid4
import zlib

from mitmproxy import http, ctx

from azuresaml import AzureSamlClient
from samllogger import SamlLogger


CONFFILE_PATH = os.getenv('CONFFILE_PATH', '/azuresaml/config.json')
DEFAULT_CONSOLE_AUTH_ENDPOINT = 'https://www.amazon.com/awsConsoleLogin'
CONSOLE_AUTH_LOGGER_NAME = 'awsConsoleLoginHook'


class AwsSamlClient(object):
    """Log into the AWS console using the SAML client to do the SAML dance"""

    LOGGER_NAME = CONSOLE_AUTH_LOGGER_NAME

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
        config = globalConfig['console_login_hook']
        self.tenantId = config['tenant_id']
        self.appId = config['app_id']
        self.enableDebugLogs = config['verbose']

    @property
    def loginUrl(self):
        requestUuid = uuid4().hex
        now = datetime.utcnow()

        samlRequest = '''
            <samlp:AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                    ID="id{}"
                    Version="2.0"
                    IssueInstant="{}Z"
                    IsPassive="false"
                    AssertionConsumerServiceURL="https://signin.aws.amazon.com/saml"
                    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
                <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">{}</Issuer>
                <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" />
            </samlp:AuthnRequest>
            '''.format(requestUuid,
                       now.isoformat(timespec='milliseconds'),
                       self.appId)

        self.debug('Using SAML request:%s', samlRequest)
        compressor = zlib.compressobj()
        samlBuffer = compressor.compress(samlRequest.encode())
        samlBuffer += compressor.flush()

        samlBase64 = base64.b64encode(samlBuffer[2:-4])

        return 'https://login.microsoftonline.com/{}/saml2?SAMLRequest={}'.format(
                self.tenantId,
                urllib.parse.quote(samlBase64))

    def doAuth(self):
        samlClient = AzureSamlClient(self.globalConfig, self.loginUrl, self.log)
        responseHtml = samlClient.submitSamlRequest(wholeResponse=True)
        headers = {
            'Referer': 'https://login.microsoftonline.com/',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Content-Type': 'text/html',
        }
        return http.HTTPResponse.make(
            200,
            responseHtml.encode(),
            headers)


class AwsConsoleLoginHook(object):

    def __init__(self, customConfigFile):
        with open(customConfigFile) as conffile:
            self.globalConfig = json.load(conffile)
        self.config = self.globalConfig['console_login_hook']
        self.hookEndpoint = self.config.get('console_auth_endpoint',
                                            DEFAULT_CONSOLE_AUTH_ENDPOINT)
        self.verbose = self.config.get('verbose', False)
        self.logger = SamlLogger(ctx.log)
        self.logger.enableDebugLogs = self.verbose

    def request(self, flow):
        """mitmproxy hook to intercept requests"""
        if flow.request.url == self.hookEndpoint:
            ctx.log.info('Intercepted request to:{}'.format(self.hookEndpoint))
            samlClient = AwsSamlClient(self.globalConfig, self.logger)
            flow.response = samlClient.doAuth()


addons = [AwsConsoleLoginHook(CONFFILE_PATH)]

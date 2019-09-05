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

Environment variables expected by this script:

    AWS_TENANT_ID:
        Tenant ID to authenticate as
    AWS_APP_ID:
        App ID to authenticate as
    AWS_CONSOLE_AUTH_ENDPOINT:
        The endpoint to treat as a request for AWS console auth. The path need
        not really exist but the domain name should (because the browser needs
        to actually resolve the domain name before sending the request to the
        proxy). Default: https://www.amazon.com/awsConsoleLogin
    AWS_CONSOLE_DEBUG:
        Turns on debug logs if this is defined.
"""


import base64
from datetime import datetime, timezone, timedelta
import logging
import logging.config
import sys
import os
import urllib.parse
from uuid import uuid4
import zlib

from mitmproxy import http, ctx

from azuresaml import AzureSamlClient


DEFAULT_CONSOLE_AUTH_ENDPOINT = 'https://www.amazon.com/awsConsoleLogin'
LOGGER_NAME = 'awsConsoleLoginHook'


class AwsSamlClient(object):
    def __init__(self, tenantId, appId, mitmLogger=None):
        self.mitmLogger = mitmLogger
        if mitmLogger:
            self.log = mitmLogger
        else:
            self.log = logging.getLogger(LOGGER_NAME)

        self.tenantId = tenantId
        self.appId = appId

    def debug(self, *args):
        if self.mitmLogger:
            # MITM logger does not accept varargs
            logStr = args[0] % (args[1:])
            self.mitmLogger.debug(logStr)
        else:
            self.log.debug(*args)

    def error(self, *args):
        if self.mitmLogger:
            # MITM logger does not accept varargs
            logStr = args[0] % (args[1:])
            self.mitmLogger.error(logStr)
        else:
            self.log.error(*args)


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
            '''.format(requestUuid, now.isoformat(timespec='milliseconds'), self.appId)

        self.debug('Using SAML request:%s', samlRequest)
        compressor = zlib.compressobj()
        samlBuffer = compressor.compress(samlRequest.encode())
        samlBuffer += compressor.flush()

        samlBase64 = base64.b64encode(samlBuffer[2:-4])

        return 'https://login.microsoftonline.com/{}/saml2?SAMLRequest={}'.format(
                self.tenantId,
                urllib.parse.quote(samlBase64))

    def doAuth(self):
        samlClient = AzureSamlClient(self.loginUrl,
                'david.koo@nswlrs.com.au',
                '/home/koo/Work/MISC/SAMLLIB/ldap-password.gpg',
                '/home/koo/Work/MISC/SAMLLIB/totp-secret.gpg')
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
    def request(self, flow):
        authReqEndpoint = os.environ.get('AWS_CONSOLE_AUTH_ENDPOINT',
                DEFAULT_CONSOLE_AUTH_ENDPOINT)
        if flow.request.url == authReqEndpoint:
            ctx.log.debug('Intercepted request to:{}'.format(authReqEndpoint))
            config = {
                'app_id': os.getenv('AWS_APP_ID'),
                'tenant_id': os.getenv('AWS_TENANT_ID'),
                'verbose': os.environ.get('AWS_CONSOLE_DEBUG', False),
            }
            flow.response = self.run(config, ctx.log)

    # (Static) methods to support running from CLI (for debugging)
    @staticmethod
    def setupLogging(loglevel):
        log_config = {
            'version': 1,
            'formatters': {
                'custom': {
                    'format': '%(levelname)s:%(funcName)s:%(lineno)d: %(message)s',
                },
            },
            'handlers': {
                'custom': {
                    'class': 'logging.StreamHandler',
                    'formatter': 'custom',
                    'level': loglevel,
                    'stream': sys.stdout,
                },
            },
            'loggers': {
                LOGGER_NAME: {
                    'level': loglevel,
                    'handlers': ['custom'],
                    'propagate': False,
                },
                'azureSamlLib': {
                    'level': loglevel,
                    'handlers': ['custom'],
                    'propagate': False,
                },
            },
            'root': {
                'level': logging.INFO,
                'handlers': ['custom'],
            },
        }
        logging.config.dictConfig(log_config)

    @staticmethod
    def run(config, logger=None):
        logLevel = logging.DEBUG if config['verbose'] else logging.INFO
        AwsConsoleLoginHook.setupLogging(logLevel)
        samlClient = AwsSamlClient(config['tenant_id'], config['app_id'], logger)
        return samlClient.doAuth()

    @staticmethod
    def main(argv):
        parser = ArgumentParser(description='SAML client for AWS Console Auth')

        parser.add_argument('-a', '--app-id',
            default=os.getenv('AWS_APP_ID', 'undefined-app'),
            help='APP ID of the AWS service')
        parser.add_argument('-t', '--tenant-id',
            default=os.getenv('AWS_TENANT_ID', 'undefined-tenant'),
            help='Tenant ID of the AWS service')
        parser.add_argument('-v', '--verbose', action='store_true',
            help='Enable verbose debug logs (passwords will NOT be revealed)')
        args = parser.parse_args(argv)

        config = {
            'app_id': args.app_id,
            'tenant_id': args.tenant_id,
            'verbose': os.environ.get('AWS_CONSOLE_DEBUG', False) or args.verbose
        }
        return AwsConsoleLoginHook.run(config)


addons = [AwsConsoleLoginHook()]


if __name__ == '__main__':
    AwsConsoleLoginHook.main(sys.argv[1:])

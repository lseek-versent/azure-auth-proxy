"""Script to use the Azure SAML library to authenticate for the AWS console.

This script is expected to be run as part of the bigger "auth proxy"
application.

The configuration options for this module should reside in the
'console_login_hook' sub-dictionary of the global configuration dictionary. The
following configuration keys are understood and will be processed:

    {
        "console_login_hook": {
            "tenant_id": "<aws_tenant_id>",
            "app_id": "<aws_app_id>"
        }
    }

    where
        tenant_id:
            Tenant ID of the AWS account to sign into
        app_id:
            App ID URI of the AWS console
"""
import base64
from datetime import datetime, timezone, timedelta
import json
import sys
import os
import urllib.parse
from uuid import uuid4
import zlib

import bottle
from azureSaml import AzureSamlClient


class AwsSamlClient(object):
    """Log into the AWS console using the SAML client to do the SAML dance"""

    CONFIG_KEY = 'console_login_hook'

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
        config = globalConfig[self.CONFIG_KEY]
        self.tenantId = config['tenant_id']
        self.appId = config['app_id']

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

    def doAuth(self, forConsole=True):
        samlClient = AzureSamlClient(self.globalConfig, self.loginUrl, self.log)
        response = samlClient.submitSamlRequest(wholeResponse=forConsole)
        headers = {
            'Content-Type': 'text/html' if forConsole else 'text/plain',
        }
        raise bottle.HTTPResponse(body=response,
                                  status=200,
                                  headers=headers)

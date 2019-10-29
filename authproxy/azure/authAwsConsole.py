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
from datetime import datetime, timezone
from functools import lru_cache
import json
import sys
import os
import urllib.parse
from uuid import uuid4
import zlib

from ..authClient import ServiceProxy
from .azureSaml import AzureSamlClient


class AwsSamlClient(ServiceProxy):
    """Log into the AWS console using the SAML client to do the SAML dance"""

    CONFIG_KEY = 'azure_aws'
    CACHE_DURATION_SECS = 60*4 + 55

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

    # The SAML assertion for AWS has a validity of 5 minutes. So if we want
    # to log into multiple consoles within a 5 minute interval we can reuse
    # the assertion without having to go through the entire SAML dance
    # again.
    #
    # Always return the whole response so that the cached response can be
    # used for both console and cli
    @lru_cache(maxsize=1)
    def getSAMLResponse(self):
        self.log.debug("Getting SAML response")
        samlClient = AzureSamlClient(self.globalConfig, self.loginUrl, self.log)
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

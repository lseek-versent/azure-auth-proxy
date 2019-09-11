"""A simple web server that performs the Azure SAML dance for various services.

The web server starts without any state and needs to be configured (via it's
HTTP API) before it can be of any use. To do so the configuration should be
POSTed to the '/configure' endpoint with 'Content-type: application/json'. The
configuration is a (JSON) dictionary with different sub-dictionaries for
different auth services. The details of configuration options for each
auth-service will be documented in the related service's script file.

The auth server itself has the following options:

    {
        "auth_server": {
            "verbose_logs": <true|false, default false>,
        }
    }

Note: The auth server defines one logger object which is passed to all other
submodules.
"""

import logging
import logging.config
import os
import sys

import bottle

from authGlobalProtect import GlobalProtectClient
from authAwsConsole import AwsSamlClient


AUTH_PROXY_PORT = 8080


class AuthProxy(bottle.Bottle):
    CONFIG_KEY = 'auth_server'
    LOGGER_NAME = 'AuthProxyLogger'

    def __init__(self):
        super(AuthProxy, self).__init__()
        self.log = None
        self.globalConfig = None
        self.config = None
        self.setupRoutes()

    def setupRoutes(self):
        self.post('/configure', callback=self.postConfig)
        self.get('/globalProtect', callback=self.proxyGlobalProtectVpn)
        self.get('/awsConsole', callback=self.proxyAwsConsole)

    def postConfig(self):
        """Receive app config into memory"""
        self.globalConfig = bottle.request.json
        self.config = self.globalConfig.get(self.CONFIG_KEY, {})
        logFile = self.config.get('logFile', 'authproxy.log')
        self.setupLogging(logFile, self.config.get('verbose_logs', False))
        self.log = logging.getLogger(self.LOGGER_NAME)

    def proxyGlobalProtectVpn(self):
        self.assertIsConfigured()
        samlClient = GlobalProtectClient(self.globalConfig, self.log)
        samlClient.doAuth()

    def proxyAwsConsole(self):
        self.assertIsConfigured()
        samlClient = AwsSamlClient(self.globalConfig, self.log)
        samlClient.doAuth()

    def proxyAwsCli(self):
        raise bottle.HTTPError(403, "Not Implemented")

    def assertIsConfigured(self):
        if not self.globalConfig:
            raise bottle.HTTPError(400, "Application is not configured")

    @classmethod
    def setupLogging(cls, logFile, verbose=False):
        log_config = {
            'version': 1,
            'formatters': {
                'custom': {
                    'format': '%(levelname)s:%(funcName)s:%(lineno)d: %(message)s',
                },
            },
            'handlers': {
                'default': {
                    'class': 'logging.StreamHandler',
                    'formatter': 'custom',
                    'stream': sys.stdout,
                },
                'authProxyFile': {
                    'class': 'logging.FileHandler',
                    'filename': logFile,
                    'formatter': 'custom',
                },
            },
            'loggers': {
                cls.LOGGER_NAME: {
                    'handlers': ['authProxyFile'],
                    'propagate': False,
                },
            },
            'root': {
                'level': logging.INFO,
                'handlers': ['default'],
            },
        }
        logging.config.dictConfig(log_config)


if __name__ == '__main__':
    authProxy = AuthProxy()
    authProxy.run(host='0.0.0.0', port=8080)

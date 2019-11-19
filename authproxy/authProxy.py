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
            "log_file": "<path to log file, optional. Default: '/authproxy/authproxy.log'>"
        }
    }

Note: The auth server defines one logger object which is passed to all other
submodules.
"""

from functools import partial
import logging
from logging.handlers import RotatingFileHandler
import os
import sys

import bottle

from .azure import AzureGlobalProtectClient, AzureAwsSamlClient
from .ping import PingAwsSamlClient, PingAtlassianClient


AUTH_PROXY_PORT = 8080


class AuthProxy(bottle.Bottle):
    DEFAULT_LOGFILE = '/authproxy/authproxy.log'
    CONFIG_KEY = 'auth_server'
    PROXY_CLASSES = {
        'azure': {
            'globalProtect': AzureGlobalProtectClient,
            'aws': AzureAwsSamlClient,
        },
        'ping': {
            'aws': PingAwsSamlClient,
            'atlassian': PingAtlassianClient,
        },
    }

    def __init__(self):
        super(AuthProxy, self).__init__()
        self.log = None
        self.globalConfig = None
        self.config = None
        self.setupRoutes()

        # These proxy objects will be created when the app is configured
        self.proxies = {
            'azure': {
                'globalProtect': None,
                'aws': None,
            },
            'ping': {
                'aws': None,
                'atlassian': None,
            },
        }
        self.azureGlobalProtectProxy = None
        self.azureAwsProxy = None
        self.pingAwsProxy = None

    def setupRoutes(self):
        self.post('/configure', callback=self.postConfig)
        self.get('/<backend>/globalProtect',
                 callback=partial(self.proxyAuth, service='globalProtect'))
        self.get('/<backend>/awsConsole',
                 callback=partial(self.proxyAuth, service='aws', forConsole=True))
        self.get('/<backend>/awsCli',
                 callback=partial(self.proxyAuth, service='aws', forConsole=False))
        self.get('/<backend>/atlassian',
                 callback=partial(self.proxyAuth, service='atlassian'))

    def postConfig(self):
        """Receive app config into memory"""
        self.globalConfig = bottle.request.json
        self.config = self.globalConfig.get(self.CONFIG_KEY, {})
        self.log = self.getLogger()

    def assertIsConfigured(self):
        if not self.globalConfig:
            raise bottle.HTTPError(400, "Application is not configured")

    def assertServiceIsSupported(self, backend, service):
        if (backend not in self.PROXY_CLASSES or
                service not in self.PROXY_CLASSES[backend]):
            raise bottle.HTTPError(400, f"{service} supported for {backend}")

    def getProxy(self, backend, service):
        self.assertIsConfigured()
        self.assertServiceIsSupported(backend, service)
        proxies = self.proxies
        if not proxies[backend][service]:
            proxyClass = self.PROXY_CLASSES[backend][service]
            proxies[backend][service] = proxyClass(self.globalConfig, self.log)
        return proxies[backend][service]

    def proxyAuth(self, backend, service, **authArgs):
        self.log.debug(f'Auth for {service}/{backend} with args:{authArgs}')
        proxyObj = self.getProxy(backend, service)
        results = proxyObj.doAuth(**authArgs)
        cookiejar = []
        if len(results) == 3:
            headers, body, cookiejar = results
        else:
            headers, body = results
        response = bottle.HTTPResponse(body=body,
                                  status=200,
                                  headers=headers)
        for cookie in cookiejar:
            response.set_cookie(cookie.name,
                                cookie.value,
                                domain=cookie.domain,
                                path=cookie.path)
        raise response

    def getLogger(self):
        verbose = self.config.get('verbose_logs', False)
        logFormat = '%(asctime)s %(levelname)s:%(funcName)s:%(lineno)d: %(message)s'
        formatter = logging.Formatter(fmt=logFormat)
        # We have to use a log file because 'bottle' seems to swallow up stdout
        # and stderr
        handler = RotatingFileHandler(self.config.get('log_file', self.DEFAULT_LOGFILE))
        handler.setFormatter(formatter)
        log = logging.getLogger(__name__)
        log.propagate = False
        log.addHandler(handler)
        log.setLevel(logging.DEBUG if verbose else logging.INFO)
        return log


def main():
    authProxy = AuthProxy()
    authProxy.run(host='0.0.0.0', port=8080, debug=True)


if __name__ == '__main__':
    main()

"""Authenticate atlassian account with PingID

This script is expected to be run as part of the bigger "auth proxy"
application.

The configuration options for this module should reside in the 'ping_atlassian'
sub-dictionary of the global configuration dictionary. The following
configuration keys are understood and will be processed:

    {
        'ping_atlassian': {
            'username': "..."
        }
    }

    where:
        username:
            Username used to log into atlassian (used to get the appropriate
            SAML request)
"""
from datetime import datetime, timezone
from functools import lru_cache

import requests

from ..authClient import ServiceProxy
from .pingSaml import PingSamlClient


class AtlassianClient(ServiceProxy):
    CONFIG_KEY = 'ping_atlassian'

    def __init__(self, globalConfig, logger):
        self.log = logger
        self.debug = self.log.debug
        self.error = self.log.error

        self.globalConfig = globalConfig
        config = globalConfig[self.CONFIG_KEY]
        self.username = config['username']
        self.csrfToken = None
        self.cookieJar = requests.cookies.RequestsCookieJar()

    def resetCookieDomains(self):
        cookieJar = requests.cookies.RequestsCookieJar()
        for cookie in self.cookieJar:
            self.debug(f'Resetting {cookie.name} domain from {cookie.domain}')
            cookieJar.set(cookie.name, cookie.value,
                          domain='atlassian.com',
                          path='/')
        return cookieJar

    def getSamlRequest(self):
        # This will take you to JIRA from which you can go anywhere else
        #
        # Overall flow:
        #   - GET csrfToken from id.atlassian.com/login
        #   - POST csrfToken and username to
        #     https://id.atlassian.com/rest/check-username and get redirect URI -
        #     SAML request will come from that URI
        #   - GET redirect URI and get the SAML request
        self.debug(f'Getting SAMLRequest for:{self.username}')
        params = {
            'continue': ['https://versent.atlassian.net/login?redirectCount=1&application=jira'],
            'application': ['jira'],
            'headers': {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:67.0) Gecko/20100101 Firefox/67.0'},
        }
        resp = requests.get('https://id.atlassian.com/login', params=params)
        resp.raise_for_status()
        csrfToken = resp.cookies['atlassian.account.xsrf.token']
        self.debug(f'Got csrfToken:{csrfToken}')
        self.cookieJar = resp.cookies
        self.debug(f"Initial cookies:{self.cookieJar}")
        self.csrfToken = csrfToken
        data = {
            'csrfToken': csrfToken,
            'username': self.username,
        }
        resp = requests.post('https://id.atlassian.com/rest/check-username',
                             params=params,
                             data=data,
                             cookies=self.cookieJar)
        resp.raise_for_status()
        self.debug(f'check-username data:{resp.json()}')
        redirectUri = resp.json()['redirect_uri']
        self.cookieJar.update(resp.cookies)
        self.debug(f"Cookies after check-username:{self.cookieJar}")
        resp = requests.get(redirectUri,
                            allow_redirects=False,
                            cookies=self.cookieJar)
        self.debug(f'Got SAMLRequest URL:{resp.headers["location"]}')
        self.cookieJar.update(resp.cookies)
        self.debug(f"Cookies after getting saml request:{self.cookieJar}")
        return resp.headers['location']

    # @lru_cache(maxsize=1)
    def getSAMLResponse(self):
        self.debug("Getting SAML response")
        requestUrl = self.getSamlRequest()
        samlClient = PingSamlClient(self.globalConfig, requestUrl, self.log)
        response, expiry = samlClient.submitSamlRequest(wholeResponse=True)
        return (samlClient, response, expiry)

    def doAuth(self):
        samlClient, response, expiry = self.getSAMLResponse()
        self.debug('Got response, expires on:%s', expiry)
        now = datetime.now(tz=timezone.utc)
        if now >= expiry:
            self.debug('Invalidating cached SAML response')
            self.getSAMLResponse.cache_clear()
            samlClient, response, _ = self.getSAMLResponse()
        else:
            self.debug('Using cached/new SAMLResponse')
        self.debug('Returning SAMLResponse:%s', response)
        headers = {
            'Content-Type': 'text/html',
            'Referer': 'https://id.versent.com.au',
        }
        resetCookies = self.resetCookieDomains()
        self.debug(f'Returning saml response with cookies:{resetCookies}')
        return (headers, response, resetCookies)

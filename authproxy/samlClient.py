"""Base class for SAML related interactions with a backend.

Different backends will have different configuration sections in the config file.
"""

import base64
from datetime import datetime
import json
import os
import os.path as osp
import re
import sys
import time
from xml.etree import ElementTree as ET

from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.common.proxy import Proxy, ProxyType



class SamlClient(object):
    """Base class for a client that does the actual SAML login dance with a
    backend."""

    LOGIN_ATTEMPTS = 3

    def __init__(self, config, requestUrl, logger):
        """Parameters:
            config:
                Global configuration object.
            requestUrl:
                URL to send the SAML request to - this initiates the SAML
                dance.
            logger:
                Instance of logger to use for logging
        """
        self.log = logger
        self.debug = self.log.debug
        self.error = self.log.error

        self.config = config
        self.requestUrl = requestUrl
        self.webdriver = self.setupSelenium()

    def setupSelenium(self):
        """Set up connection with the (remote) selenium server"""
        self.debug('Setting up selenium')
        desired_capabilities = DesiredCapabilities.FIREFOX.copy()
        proxy = Proxy()
        proxy.proxyType = ProxyType.MANUAL
        proxy.httpProxy = "localhost:8085"
        proxy.sslProxy = "localhost:8085"
        proxy.add_to_capabilities(desired_capabilities)

        driver = webdriver.Remote(
                command_executor='http://127.0.0.1:4444/wd/hub',
                desired_capabilities=desired_capabilities)

        return driver

    def submitSamlRequest(self, wholeResponse=False):
        """Perform the actual SAML login dance.

        Returns either the whole original /SAS/ProcessAuth response
        (wholeResponse == True) or just the SAMLResponse string (wholeResponse
        == False)"""
        raise NotImplementedError

    def getOriginalResponse(self, responsePage):
        """Extract original (intercepted) HTML response from IDP"""
        self.debug('Extracting original response from:%s', responsePage)
        match = re.search("__START_ORIGINAL_RESPONSE__:(.*):__END_ORIGINAL_RESPONSE__", responsePage)
        originalEncodedResponse = match.group(1)
        originalResponse = base64.b64decode(originalEncodedResponse).decode()
        self.debug('Got original response:%s', originalResponse)
        return originalResponse

    def extractSamlResponse(self, responseHtml):
        """Extract the SAML assertion from the original (intercepted) HTML
        response"""
        soup = BeautifulSoup(responseHtml, 'html.parser')
        samlResponse = soup.find('input', {'name': 'SAMLResponse'}).get('value')
        self.debug('Original Saml Response:%s', samlResponse)
        return samlResponse

    def getExpiryTime(self, samlResponse):
        xmlAssertion = base64.b64decode(samlResponse).decode()
        self.log.debug('Parsing at assertion:%s', xmlAssertion)
        root = ET.fromstring(xmlAssertion)
        condTag = '{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData'
        xpathExpr = ".//{}".format(condTag)
        conditions = root.findall(xpathExpr)
        assert len(conditions) == 1, "No unique assertion conditions found"
        cond = conditions[0]
        expiryStr = cond.get('NotOnOrAfter')
        self.log.debug('Got expiry string:%s', expiryStr)
        # Python does not handle the 'Zulu time' suffix and 3.6 does not
        # have fromisoformat class method T_T
        expiryStr = re.sub('Z$', '+0000', expiryStr)
        dateformat = '%Y-%m-%dT%H:%M:%S.%f%z'
        expiry = datetime.strptime(expiryStr, dateformat)
        self.debug("SAML assertion expiry time:%s", expiry)
        return expiry

"""Library for performing Ping based SAML login.

PING sucks bigtime ... it does not give you access to your TOTP secret and so
you either need to install their mobile app or a desktop app. If you don't want
either you'll get the TOTP token via email.

This library takes in configuration as a dict object and reads configuration
under the "ping" section of the config object:

    {
        "ping": {
            "ping_username": ...,
            "ping_password": ...,
            "imap_server": ...,
            "imap_port": ...,
            "imap_username": ...,
            "imap_password": ...,
            "verbose": <true|false, default false>
        }
    }
"""

import base64
from datetime import datetime
import json
from pprint import pprint
import re
import time
from xml.etree import ElementTree as ET

from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.proxy import Proxy, ProxyType
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from ..samlClient import SamlClient
from .pingImapReader import PingImapReader


CONFIG_KEY = 'ping'


class PingSamlClient(SamlClient):
    """A client that does the SAML login dance with PingID."""

    LOGIN_ATTEMPTS = 3
    AJAX_WAIT_SECS = 10

    def __init__(self, config, requestUrl, logger):
        """Parameters:
            config:
                Configuration object that contains the saml library config
                (under the key specified by $CONFIG_KEY).
            requestUrl:
                URL to send the SAML request to - this initiates the SAML
                dance.
            logger:
                Instance of logger to use for logging
            skipToken:
                Skip the token input state, assume username + password is
                enough.
        """
        super().__init__(config, requestUrl, logger)
        libConfig = config[CONFIG_KEY]
        self.pingUsername = libConfig['ping_username']
        self.pingPassword = libConfig['ping_password']
        self.imapUsername = libConfig['imap_username']
        self.imapPassword = libConfig['imap_password']
        self.imapServer = libConfig['imap_server']
        self.imapPort = libConfig['imap_port']
        self.debug('Using username:%s', self.pingUsername)

    def sendInput(self, elementName, value):
        element = self.webdriver.find_element_by_name(elementName)
        element.clear()
        element.send_keys(value)

    def waitFor(self, cssSelector):
        wait = WebDriverWait(self.webdriver, self.AJAX_WAIT_SECS)
        waitCondition = (By.CSS_SELECTOR, cssSelector)
        return wait.until(EC.element_to_be_clickable(waitCondition))

    def submitUsernamePassword(self):
        self.sendInput('pf.username', self.pingUsername)
        self.sendInput('pf.pass', self.pingPassword)
        element = self.webdriver.find_element_by_css_selector('a[title="Sign On"]')
        element.click()

    def submitToken(self):
        element = self.waitFor('input[id="otp"]')
        imapClient = PingImapReader(self.imapServer,
                                    self.imapPort,
                                    self.imapUsername,
                                    self.imapPassword,
                                    self.log)
        token = imapClient.getOtpEmail()
        element.send_keys(token)
        element.send_keys(Keys.TAB)
        element.send_keys(Keys.TAB)
        element.send_keys(Keys.ENTER)
        # element = self.webdriver.find_element_by_css_selector('input[type="submit"]')
        # element.click()

    def submitTokenOrExtractResponse(self):
        # sometimes we don't need to submit the token (already 'verified' once)
        # So when trying to submit token we try to see whether or not the page
        # already has a SAML response. If so, we skip token submission. A comma
        # in the CSS selector is an "OR"
        token_selector = 'input[id="otp"]'
        response_selector = '[name="SAMLResponse"]'
        self.waitFor(f'{token_selector}, {response_selector}')
        element = None
        try:
            element = self.webdriver.find_element_by_css_selector(token_selector)
        except NoSuchElementException:
            self.debug('No token selector found')
        else:
            self.submitToken()

        self.waitFor('[name=SAMLResponse]')
        self.debug('Got saml response')
        return self.webdriver.page_source

    def submitSamlRequest(self, wholeResponse=False):
        """Perform the actual SAML login dance.

        Returns either the whole original /SAS/ProcessAuth response
        (wholeResponse == True) or just the SAMLResponse string (wholeResponse
        == False)"""
        self.debug("GET %s", self.requestUrl)
        self.webdriver.get(self.requestUrl)
        self.submitUsernamePassword()
        # self.submitToken()

        # Wait for SAML exchange to finish
        responsePage = self.submitTokenOrExtractResponse()
        originalResponse = self.getOriginalResponse(responsePage)

        # # Wait a bit more to debug the handling of the next step
        # time.sleep(20)
        self.webdriver.close()
        samlResponse = self.extractSamlResponse(originalResponse)
        expiry = self.getExpiryTime(samlResponse)
        return (originalResponse if wholeResponse else self.extractSamlResponse(originalResponse), expiry)

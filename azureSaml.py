"""Library for performing Azure based SAML login

This library takes in configuration as a dict object and reads configuration
under the "saml_lib" section of the config object:

    {
        "saml_lib": {
            "username": ...,
            "password_file": ...,
            "totp_secret_file": ...,
            "skip_token": <true|false, default false>
            "verbose": <true|false, default false>
        }
    }
"""

from argparse import ArgumentParser
import base64
import getpass
import json
import logging
import logging.config
import os
import os.path as osp
from pprint import pprint
import re
import sys
import time

from bs4 import BeautifulSoup
import pyotp
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.common.proxy import Proxy, ProxyType
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


CONFFILE_PATH = os.getenv('CONFFILE_PATH', '/azuresaml/config.json')
SAMLLIB_LOGGER = 'azureSamlLib'
CONFIG_KEY = 'saml_lib'


class PageState(object):
    """A state of the page in the login flow.

    Encapsulates the process of selecting a required element from the page
    using a CSS selector (after ensuring it is editable), entering the required
    value and finally clicking the correct button to move to the next step of
    the login process."""

    # How long to wait for AJAX handlers to complete (and actually show up the
    # required element).
    AJAX_WAIT_SECS = 10

    # The CSS selector to find the required field in the page
    fieldSelector = None  # must be overridden by subclasses

    # The CSS selector to find the "Next" button in the page (if any)
    nextSelector = None  # should usually be overridden by subclasses

    def __init__(self, driver, value, logger=None):
        """Parameters:
            driver:
                The selenium web driver to use for interactions
            value:
                The value to input into the selected field.
        """

        self.log = logger
        self.debug = self.log.debug
        self.error = self.log.error
        self.nextState = None
        self.driver = driver
        self.value = value

    @classmethod
    def waitFor(cls, webdriver, css_selector):
        wait = WebDriverWait(webdriver, cls.AJAX_WAIT_SECS)
        waitCondition = (By.CSS_SELECTOR, css_selector)
        return wait.until(EC.element_to_be_clickable(waitCondition))

    def process(self):
        self.debug("Processing [%s]", self.__class__.__name__)
        element = self.waitFor(self.driver, self.fieldSelector)
        if self.value:
            element.clear()
            element.send_keys(self.value)
        if self.nextSelector:
            self.debug("Clicking 'Next'")
            nextButton = self.waitFor(self.driver, self.nextSelector)
            # Use 'click()' instead of 'submit()' because ajax related handlers are
            # triggered on click and not submit.
            nextButton.click()
        self.debug("Finished [%s]", self.__class__.__name__)


class UsernameInput(PageState):
    # Values shamelessly ripped off from dtjohnson/aws-azure-login
    fieldSelector = 'input[name="loginfmt"]:not(.moveOffScreen)'
    nextSelector  = 'input[type=submit][value="Next"]'


class PasswordInput(PageState):
    # Values shamelessly ripped off from dtjohnson/aws-azure-login
    fieldSelector = ('input[name="Password"]:not(.moveOffScreen),'
                     'input[name="passwd"]:not(.moveOffScreen)')
    nextSelector  = 'span[class=submit],input[type=submit]'


class TokenInput(PageState):
    # Values shamelessly ripped off from dtjohnson/aws-azure-login
    fieldSelector = 'input[name="otc"]'
    nextSelector = 'input[type=submit]'


class AzureSamlClient(object):
    """A client that does the actual SAML login dance.

    The client takes a URL (which would include the SAML request) to initiate
    the SAML login sequence along with credentials, performs the dance, and
    returns the SAML response as a string."""

    LOGIN_ATTEMPTS = 3

    def __init__(self, config, requestUrl, logger):
        """Parameters:
            config:
                Configuration object that contains the saml library config
                (under the "saml_lib" key).
            requestUrl:
                URL to send the SAML request to - this initiates the SAML
                dance.
            logger:
                Instance of logger to use for logging
            skipToken:
                Skip the token input state, assume username + password is
                enough.
        """
        self.log = logger
        self.debug = self.log.debug
        self.error = self.log.error

        self.requestUrl = requestUrl
        libConfig = config['saml_lib']
        self.username = libConfig['username']
        self.password = libConfig['password']
        self.skipToken = libConfig.get('skip_token', False)
        if not self.skipToken:
            self.totpSecret = libConfig['totp_secret']
            self.totpToken = pyotp.TOTP(self.totpSecret).now()
        self.debug('Using username:%s', self.username)
        self.webdriver = self.setupSelenium()
        self.startState = self.setupStates()

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

    def setupStates(self):
        """Define and connect the states required login flow"""
        usernameState = UsernameInput(self.webdriver,
                                      self.username,
                                      self.log)
        passwordState = PasswordInput(self.webdriver,
                                      self.password,
                                      self.log)
        usernameState.nextState = passwordState
        if not self.skipToken:
            tokenState = TokenInput(self.webdriver,
                                    self.totpToken,
                                    self.log)
            passwordState.nextState = tokenState
        else:
        return usernameState

    def submitSamlRequest(self, wholeResponse=False):
        """Perform the actual SAML login dance.

        Returns either the whole original /SAS/ProcessAuth response
        (wholeResponse == True) or just the SAMLResponse string (wholeResponse
        == False)"""
        self.debug("GET %s", self.requestUrl)
        self.webdriver.get(self.requestUrl)
        for attempt in range(self.LOGIN_ATTEMPTS):
            self.debug("ATTEMPT:%d", attempt)
            currState = self.startState
            while currState:
                currState.process()
                currState = currState.nextState
            else:
                self.debug("Finished processing all states")
                break
        else:
            self.error("Unable to log in after %s attempts",
                    self.LOGIN_ATTEMPTS)
            return None

        # Wait for SAML exchange to finish
        PageState.waitFor(self.webdriver, '[name=SAMLResponse]')
        responsePage = self.webdriver.page_source
        originalResponse = self.getOriginalResponse(responsePage)

        # # Wait a bit more to debug the handling of the next step
        # time.sleep(20)
        self.webdriver.close()
        return originalResponse if wholeResponse else self.extractSamlResponse(originalResponse)

    def getOriginalResponse(self, responsePage):
        self.debug('Extracting original response from:%s', responsePage)
        match = re.search("__START_ORIGINAL_RESPONSE__:(.*):__END_ORIGINAL_RESPONSE__", responsePage)
        originalEncodedResponse = match.group(1)
        originalResponse = base64.b64decode(originalEncodedResponse).decode()
        self.debug('Got original response:%s', originalResponse)
        return originalResponse

    def extractSamlResponse(self, responseHtml):
        soup = BeautifulSoup(responseHtml, 'html.parser')
        samlResponse = soup.find('input', {'name': 'SAMLResponse'}).get('value')
        self.debug('Original Saml Response:%s', samlResponse)
        return samlResponse


# Used only when invoked from the command line (i.e. during testing).
def setupLogging(loglevel=logging.INFO):
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
                'stream': sys.stdout,
            },
        },
        'loggers': {
            SAMLLIB_LOGGER: {
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


# Used only when invoked from the command line (i.e. during testing).
def main(argv):
    parser = ArgumentParser(description='Azure SAML client')

    parser.add_argument('-c', '--config-file', default=CONFFILE_PATH,
        help='Path to the config file')
    parser.add_argument('-w', '--whole-response', action='store_true',
        help=('Return the whole auth response doc rather than just the '
              'SAMLResponse string'))
    parser.add_argument('url',
        help='The URL to submit the SAML login request to')
    args = parser.parse_args(argv)

    import json
    with open(args.config_file) as cfgfile:
        globalConfig = json.load(cfgfile)
    setupLogging()
    logger = logging.getLogger(SAMLLIB_LOGGER)
    if globalConfig[CONFIG_KEY]['verbose_logs']:
        logger.setLevel(logging.DEBUG)
    samlClient = AzureSamlClient(globalConfig, args.url, logger)
    response = samlClient.submitSamlRequest(args.whole_response)
    print(response, end='')


if __name__ == '__main__':
    main(sys.argv[1:])

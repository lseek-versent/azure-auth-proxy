"""Library for performing Azure based SAML login

Since this library will (ultimately) run from an mitmproxy addon it can't
really use command line arguments to configure its parameters. Instead if
relies on environment variables:

    SAML_USERNAME:
        User to authenticate as
    SAML_PASSWORD_FILE:
        Path to GPG encrypted file (inside the container) that holds the
        password to use.
    SAML_TOTP_SECRET_FILE:
        Path to GPG encrypted file (inside the container) that holds the
        TOTP secret from which tokens are generated.

If the command line arguments are specifed (as during debugging) then the
command line arguments take priority.
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
import gnupg
import pyotp
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.common.proxy import Proxy, ProxyType
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


class ObjectWithLogger(object):
    def __init__(self, mitmLogger=None):
        self.mitmLogger = mitmLogger
        if mitmLogger:
            self.log = mitmLogger
        else:
            self.log = logging.getLogger("azureSamlLib")

    def debug(self, *args):
        if self.mitmLogger:
            # MITM logger does not accept varargs :(
            logStr = args[0] % (args[1:])
            self.mitmLogger.debug(logStr)
        else:
            self.log.debug(*args)

    def error(self, *args):
        if self.mitmLogger:
            # MITM logger does not accept varargs :(
            logStr = args[0] % (args[1:])
            self.mitmLogger.error(logStr)
        else:
            self.log.debug(*args)

    def withDebug(self, value, *debugArgs):
        self.debug(*debugArgs)
        return value


class PageState(ObjectWithLogger):
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

    def __init__(self, driver, value):
        """Parameters:
            driver:
                The selenium web driver to use for interactions
            value:
                The value to input into the selected field.
        """

        super(PageState, self).__init__()
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


class AzureSamlClient(ObjectWithLogger):
    """A client that does the actual SAML login dance.

    The client takes a URL (which would include the SAML request) to initiate
    the SAML login sequence along with credentials, performs the dance, and
    returns the SAML response as a string."""
    LOGIN_ATTEMPTS = 3

    def __init__(self, requestUrl, username, passwordFile, totpSecretFile):
        """Parameters:
            requestUrl:
                The URL to GET to initiate the SAML login sequence (and
                contains the SAML request object).
            username:
                The username to log in as.
            passwordFile:
                (GPG encrypted) file that contains the password for the user.
            totpSecret:
                (GPG encrypted) file that contains the OTP secret. The OTP
                token will be generated from this secret.
        """
        super(AzureSamlClient, self).__init__()

        self.requestUrl = requestUrl
        self.username = username
        self.password, totpSecret = self.getCredentials(passwordFile, totpSecretFile)
        self.totpToken = pyotp.TOTP(totpSecret).now()
        self.debug('Using username:%s', self.username)

        self.webdriver = self.setupSelenium()
        self.startState = self.setupStates()

    def getCredentials(self, passwordFile, totpSecretFile):
        gpgHome = osp.join(os.environ.get("HOME"), ".gnupg")
        pubring = osp.join(gpgHome, 'pubring.kbx')
        secring = osp.join(gpgHome, 'private-keys-v1.d')
        gpg = gnupg.GPG(gnupghome=gpgHome, use_agent=True,
            keyring=pubring, secret_keyring=secring)

        def decrypt(secretFile):
            with open(secretFile, 'rb') as sFile:
                secret = gpg.decrypt_file(sFile)
                assert secret.ok, \
                    '{} decryption failed:{}'.format(secretFile, secret.status)
            return str(secret)

        password = decrypt(passwordFile)
        totpSecret = decrypt(totpSecretFile)
        return (password, totpSecret)

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
        usernameState = UsernameInput(self.webdriver, self.username)
        passwordState = PasswordInput(self.webdriver, self.password)
        tokenState = TokenInput(self.webdriver, self.totpToken)
        usernameState.nextState = passwordState
        passwordState.nextState = tokenState
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
        return self.withDebug(samlResponse, 'SAMLResponse:%s', samlResponse)


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
            'thisApp': {
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


def main(argv):
    parser = ArgumentParser(description='Azure SAML client')

    parser.add_argument('-p', '--password-file',
        default=os.environ.get('SAML_PASSWORD_FILE', 'password.gpg'),
        help='Path to the (gpg encrypted) file that contains the password')
    parser.add_argument('-t', '--totp-secret-file',
        default=os.environ.get('SAML_TOTP_SECRET_FILE', 'totp-secret.gpg'),
        help='Path to the (gpg encrypted) file that contains the OTP secret')
    parser.add_argument('-u', '--username',
        default=os.environ.get('SAML_USERNAME', 'will@not.work.com'),
        help='Username to use to log in')
    parser.add_argument('-v', '--verbose', action='store_true',
        help='Enable verbose debug logs (passwords will NOT be revealed)')
    parser.add_argument('-w', '--whole-response', action='store_true',
        help=('Return the whole auth response doc rather than just the '
              'SAMLResponse string'))
    parser.add_argument('url',
        help='The URL to submit the SAML login request to')
    args = parser.parse_args(argv)

    setupLogging(logging.DEBUG if args.verbose else logging.INFO)
    logger = logging.getLogger('thisApp')
    samlClient = AzureSamlClient(args.url,
            args.username,
            args.password_file,
            args.totp_secret_file)
    response = samlClient.submitSamlRequest(args.whole_response)
    print(response, end='')


if __name__ == '__main__':
    main(sys.argv[1:])

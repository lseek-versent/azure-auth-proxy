"""A base class to encapsulate mitmproxy.ctx and logging.Logger

We want to be able to emit debug logs during debugging when scripts typically
run stand-alone (esp. the SAML lib module) as well as (if enabled) during
execution in mitmproxy.

But the mitmproxy.ctx logger has a different interface than the logging.Logger
interface - the mitmproxy.ctx logger does not accept varargs. The mitmproxy.ctx
logger also does not have different log handlers - logging at debug level in
mitmproxy loger means it shows up only if you enable verbose logging in
mitmproxy and that results in a lot of other (mitmproxy) logs.

Therefore we create a wrapper class that abstracts the two types of loggers and
provides a uniform interface to subclasses and, when using the mitmproxy, emit
debug logs (if enabled) at info level so that they easily visible.
"""

import logging


class SamlLogger(object):

    def __init__(self, logger=None):
        self.log = logger
        self._showDebugLogs = False

    @property
    def enableDebugLogs(self):
        return self._showDebugLogs

    @enableDebugLogs.setter
    def enableDebugLogs(self, value):
        self._showDebugLogs = True
        if isinstance(self, logging.Logger):
            self.log.setLevel(logging.DEBUG)

    def debug(self, *args):
        if isinstance(self, logging.Logger):
            self.log.debug(*args)
        elif self._showDebugLogs:
            logStr = args[0] % (args[1:])
            self.log.info(logStr)

    def info(self, *args):
        if isinstance(self, logging.Logger):
            self.log.info(*args)
        elif self._showDebugLogs:
            logStr = args[0] % (args[1:])
            self.log.info(logStr)

    def error(self, *args):
        if isinstance(self, logging.Logger):
            self.log.error(*args)
        else:
            logStr = args[0] % (args[1:])
            self.log.error(logStr)

    def withDebug(self, value, *debugArgs):
        """Emit a debug message and return a value"""
        self.debug(*debugArgs)
        return value

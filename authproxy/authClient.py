"""Base class for an auth proxy service client"""


class ServiceProxy(object):
    """Base class for a service proxied by the auth proxy"""
    CONFIG_KEY = None  # MUST be overridden by sub classes

    def __init__(self, globalConfig, logger):
        self.log = logger
        self.debug = self.log.debug
        self.error = self.log.error

        self.globalConfig = globalConfig
        self.config = globalConfig[self.CONFIG_KEY]

        def doAuth(self, **kwargs):
            raise NotImplementedError

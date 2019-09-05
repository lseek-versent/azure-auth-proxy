"""Intercept response to Azure SAML auth workflow

More specifically, intercept the response to the
/SAS/ProcessAuth request, base64 encrypt it and "wrap" it around an easily
parsable HTML comment (so that selennium/firefox does not try to parse it).

Note that the comment needs to reside within the
<html>...</html> document else Selenium seems to discard
it."""

import base64

from mitmproxy import http, ctx

class ProcessAuthHook(object):

    def response(self, flow):
        requestObj = flow.request
        if requestObj.url.endswith('/SAS/ProcessAuth'):
            ctx.log.info('Intercepted SAML ProcessAuth response')
            responseObj = flow.response
            origContents = responseObj.get_text()
            origEncoded = base64.standard_b64encode(origContents.encode())
            newContents = ('<html><body><p name="SAMLResponse">'
                           'Login Successful'
                           '</p>'
                           '<script type="text/javascript">/* __START_ORIGINAL_RESPONSE__:')
            newContents += origEncoded.decode()
            newContents += (':__END_ORIGINAL_RESPONSE__ */</script>'
                            '</body></html>')
            ctx.log.info('response headers:{}'.format(responseObj.headers.items()))
            ctx.log.info('setting contents to:{}'.format(newContents))
            responseObj.set_text(newContents)

addons = [ProcessAuthHook()]

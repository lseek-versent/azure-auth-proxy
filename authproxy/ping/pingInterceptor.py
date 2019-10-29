"""Intercept response to PingID SAML auth workflow"""

import base64

from mitmproxy import http, ctx

class PingInterceptor(object):

    def response(self, flow):
        requestObj = flow.request
        if requestObj.url.endswith('/resumeSAML20/idp/startSSO.ping'):
            responseObj = flow.response
            origContents = responseObj.get_text()
            if 'SAMLResponse' in origContents:
                ctx.log.info('Intercepted SAML ProcessAuth response')
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

addons = [PingInterceptor()]

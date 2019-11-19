FROM selenium/standalone-firefox:3.141.59-titanium

USER root

RUN mkdir -p /authproxy/confdir && \
        chown -R seluser.seluser /authproxy && \
        apt-get update && \
        apt-get install --no-install-recommends -y python3-setuptools python3-pip && \
        rm -f /etc/supervisor/supervisord.conf /etc/supervisord.conf

COPY ./ /tmp/src/
RUN mv /tmp/src/supervisor-conf/authproxy.conf \
       /tmp/src/supervisor-conf/saml-interceptor.conf \
       /etc/supervisor/conf.d && \
    mv /tmp/src/supervisor-conf/supervisord.conf /etc/ && \
    pip3 --no-cache-dir install /tmp/src

USER seluser


# vim:ft=dockerfile

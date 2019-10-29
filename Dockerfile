FROM selenium/standalone-firefox:3.141.59-titanium

USER root

RUN mkdir -p /authproxy/confdir && \
        chown -R seluser.seluser /authproxy && \
        apt-get update && \
        apt-get install --no-install-recommends -y python3-setuptools python3-pip && \
        rm -f /etc/supervisor/supervisord.conf

COPY supervisor-conf /tmp/supervisor-conf
RUN mv /tmp/supervisor-conf/authProxy.conf \
       /tmp/supervisor-conf/mitmdump.conf \
       /etc/supervisor/conf.d && \
    mv /tmp/supervisor-conf/supervisord.conf /etc/

COPY ./ /tmp/src/
RUN pip3 --no-cache-dir install /tmp/src

USER seluser


# vim:ft=dockerfile

FROM selenium/standalone-firefox:3.141.59-titanium

USER root
COPY requirements.txt /tmp
RUN mkdir -p /azuresaml/confdir && \
    apt-get update && \
    apt-get install --no-install-recommends -y python3-setuptools python3-pip oathtool && \
    pip3 --no-cache-dir install -r /tmp/requirements.txt && \
    mkdir -p /home/seluser/.gnupg && \
    echo "default-cache-ttl 9600" > /home/seluser/.gnupg/gpg-agent.conf && \
    chown -R seluser.seluser /home/seluser/.gnupg /azuresaml && \
    chmod go-rwx /home/seluser/.gnupg

USER seluser
COPY aws_console_login_hook.py saml_process_hook.py azuresaml.py samllogger.py /azuresaml/
COPY mitmdump.conf /etc/supervisor/conf.d/


# vim:ft=dockerfile
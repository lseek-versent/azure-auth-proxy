# A web app to authenticate services against some SAML backends

Currently known backends are:

* Azure AD
* Ping ID

## Building

1. Clone this repository
2. `docker build -t <your image tag> .`

The resulting image will run selenium + firefox in headless mode to do the auth
dance. To debug the auth dance use the `Dockerfile-debug` file: `docker build
-t <your image tag> -f Dockerfile-debug .`

This will build a docker image that has a `vncserver` running in it. Connecting
to this `vncserver` using a VNC client (like `vncviewer`) should show you the
browser/server UI interaction that happens behind the scenes.

## Running

### Start the container
```sh
docker run --name authproxy \
    --rm \
    -p 127.0.0.1:8080:8080 \
    <your image tag>
```

If running the debug image, you need to publish the vnc server port as well:

```sh
docker run --name authproxy \
    --rm \
    -p 127.0.0.1:5900:5900 \
    -p 127.0.0.1:8080:8080 \
    <your image tag>
```

The VNC connection password is `secret`.

### Configure the app

```sh
gpg --decrypt config.json.gpg | curl -d @- \
    -H "Content-type: application/json" \
    http://localhost:8080/configure
```

### `GET` an endpoint

```sh
curl http://localhost:8080/azure/globalProtect # gives prelogin cookie
```

The general format of an end point is:

    http://localhost:8080/<saml-backend>/<service>

where `saml-backend` is either `azure` or `ping`. As of now the following services are supported

|Service        | Azure | Ping | Description                      |
|---------------|-------|------|----------------------------------|
| globalProtect | Yes   | No   | The PaloAlto GlobalProtect VPN   |
| awsCli        | Yes   | Yes  | SAML assertion for AWS CLI       |
| awsConsole    | Yes   | Yes  | For logging into the AWS console |
| atlassian     | No    | Yes  | For logging into versent atlassian |

## Components

The `authProxy` application contains the following components in its `authproxy` `python` package:

* authProxy: Main `bottle` application that serves as the "auth proxy". Source file: `authProxy.py`
* sub-packages for each supported SAML backend:
    * `azure`: Files related to Azure AD SAML IDP
    * `ping`: Files related to PingID SAML IDP

Within each sub-package there is a module that does the actual interaction with
the IDP (`azureSaml.py` / `pingSaml.py`) and clients that use this common
module to provide auth proxies for various services.


## Basic Flow

         Host           Docker Container      Intertubes

       +--------+  (1)  +-------------+       +------+
       | Client |<----->| Auth proxy  |       | SAML |
       +--------+  (7)  |   server    |       | IDP  |
                        +--+-------^--+       +---.--+
                           |      /|\            /|\
                        (2)|       |(6)           |
                          \|/      |              |
                        +--v-------+--+           |
                        |Service Proxy|           |
                        +--+-------^--+           |
                           |      /|\             |
                        (3)|       |(5)           |
                          \|/      |              |
                        +--v-------+--+  (4)      |
                        |  SAML lib   |<----------+
                        +-------------+


1. The client (browser/`curl`/shell script) does an HTTP `GET` on an end point on
   the auth proxy which runs in a docker container. For the sake of security
   the docker container *must* be configured to publish only to the local host
   network interface so that only the local host can access the auth proxy
   service.
2. Each service proxy as an end point on the auth proxy server. Control is
   transferred to the service proxy depending on the end-point requested.
3. The service proxy uses the SAML library to perform the SAML dance and get
   the SAML Response XML.
4. The IDP ultimately sends the SAML Response XML to the SAML library which
   returns it to the service proxy.
5. The service proxy uses the SAML response to complete the auth request and
   returns the result to the client.


## Configuration
The auth proxy starts out as an "empty" service listening on port 8080 (which,
as mentioned before, should be published to a port only on the localhost for
security). At this stage it needs to be configured before it the service
proxies can provide service. This is done by `POST`ing a configuration JSON to
the `/configure` end point:

```sh
curl -H "Content-type: application/json" \
    -d @config.json \
    http://localhost:8080/configure
```


This configuration file is a dictionary of dictionaries, with each section
holding the configuration for a particular module:

```json
{
    "auth_server": {
        "verbose_logs": <true|false, default false>,
        "log_file": "<path to log file, optional. Default: /azuresaml/authproxy.log>"
    },

    "azure": {
        "username": "<username to log into AD as",
        "password": "<password for the user>",
        "totp_secret": "<totp generator secret>"
    },

    "azure_aws": {
        "tenant_id": "<AWS tenant ID>",
        "app_id": "<APP ID URI>"
    },

    "azure_globalprotect": {
        "server_url": "<Base URL to GlobalProtect VPN server>"
    },

    "ping": {
        "ping_username": "<username to log into PingID as>",
        "password": "<password for the user>",
        "imap_server": "<IMAP server to get one-time tokens from>",
        "imap_port": "<IMAP port to connect to>",
        "imap_username": "<username to log into IMAP mailbox",
        "imap_password": "<password for IMAP user"
    },

    "ping_aws": {
        "login_url": "<URL to AWS console FROM VERSENT PING desktop page>"
    },

    "ping_atlassian": {
        "username": "<versent atlassian account username>"
    }

}
```

The sections that are currently understood by the authProxy app are:

* `auth_server`: Configuration for the authProxy app itself.
* `azure`: Configuration for Azure AD IDP.
* `azure_aws`: AWS configuration for Azure AD IDP
* `azure_globalprotect`: GlobalProtectClient configuration for Azure AD IDP.
* `ping`: Configuration for PingID IDP.
* `ping_aws`: AWS configuration for PingID IDP
* `ping_atlassian`: Atlassian configuration for PingID IDP

Since this configuration contains secrets it is not advisable to save this to a
cleartext file. Instead it should be saved to an encrypted file and decrypted
and passed to `curl` (or any other client) when required:

```sh
gpg --decrypt config.json.gpg | curl -d @- \
    -H "Content-type: application/json" \
    http://localhost:8080/configure
```


## Endpoints and service proxies


### `POST /configure`
This endpoint accepts only a `POST` request. Use this endpoint to configure the
auth proxy app. See [Link](#configuration)


### `GET /azure/globalProtect`
`GET` this endpoint to get the GlobalProtect VPN prelogin cookie. This cookie
can then be supplied to `openvpn` to log into the GlobalProtect VPN (would
probably need to `sudo` first):

```sh
curl http://localhost:8080/azure/globalProtect | \
openconnect --protocol=gp \
    --usergroup gateway:prelogin-cookie \
    -u <vpn-username> \
    --passwd-on-stdin \
    --os mac-intel \
    <vpn-server-url>/login.esp/:prelogin-cookie
```

NOTE: GlobalProtect VPN does **NOT** support Linux. Therefore when using Linux
to log into GlobalProtect VPN you need to trick the server into thinking it's
either a windoze or a mac system (hence the `--os mac-intel` command line
option).

### `GET /azure/awsConsole`, `GET /ping/awsConsole`
`GET` the AWS console account selection page for Azure / Ping IDP respectively.

#### Some important background
The SAML auth process, in very simple terms, is as follows:

Client (browser for the case of AWS console login):
    `GET` some service URL
Service:
    302 to IDP with login related parameters (mainly the SAML auth request)
Client:
    Auth with IDP
IDP:
    Return an HTML form which when submitted will tell the service client has
    been authenticated.


The `azureSaml.py` and `pingSaml.py` modules return this HTML form to the
corresponding `authAwsConsole.py` module which returns this back to the client
browser. But when the browser submits this form *if the auth server hostname is
NOT of the form \*.amazon.com then the AWS service rejects the response*,
claiming no SAML response was provided to it.

If, however, the auth server hostname *IS* of the form \*.amazon.com, the AWS
service accepts it. CORS? Unfortunately, I don't understand enough of web design
and protocols to know why.

The bottom line, then, is that we need to fool the browser into thinking that it
is talking to an amazon server when talking to the auth proxy (at least for the
case of AWS console login). On Linux systems this can be easily achieved by
editing the `/etc/hosts` file and creating a fictitious entry for the auth proxy
server:

    127.0.0.1  anynameyouwant.amazon.com

and then pointing the browser to
http://anynameyouwant.amazon.com:8080/<azure|ping>/awsConsole

### `GET /azure/awsCli`, `GET /ping/awsCli`
`GET` the SAML assertion from the Azure / Ping IDP respectively. This assertion
can then be used to log in via the CLI e.g. by using the `aws sts
assume-role-with-saml` command line or by using the
https://github.com/lseek-versent/awscli_multilogin utility to log into
multiple AWS accounts with the same SAML assertion.

### `GET /ping/atlassian`
Similar to AWS console except for Atlassian login. This always takes you to the JIRA page from where you can jump to any other Atlassian application. Note: just as for the aws console, you need a fake `atlassian.com` domain name alias to make it work. E.g.

    127.0.0.1 mylogin.atlassian.com

and then point the browser to http://mylogin.atlassian.com:8080/ping/atlassian

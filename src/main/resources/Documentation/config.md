Configuration
=============

## Registering a Client for Gerrit

Gerrit must be registered as client with the [CloudFoundry User Account and
Authentication (UAA) Server](https://github.com/cloudfoundry/uaa) that acts
as OAuth2 authentication and authorization backend.

The following sequence assumes that the UAA client application (`uaac`) is
installed. It will create a client with name `gerrit`.

```
  uaac target <URL of the UAA server>

  uaac token client get admin

  uaac client add gerrit
    --authorities uaa.resource
    --authorized_grant_type authorization_code,refresh_token,password
    --scope openid
    --autoapprove openid
    --access_token_validity <time in seconds>
    --redirect_uri <URL of the Gerrit server>/oauth
    --secret <client secret>
```

Make sure to choose a reasonable access token validity if you want to use
access tokens to authenticate Git-over-HTTP communication. If tokens expire
too often using them with a native Git client might be cumbersome.
On the other side, acccess tokens should be treated like passwords and
should be changed from time to time for security reasons.

Make sure to choose a strong password for `secret`. Gerrit uses
this password to obtain access tokens on behalf of its users.

## Configuring the @PLUGIN@ Plugin

The configuration of the @PLUGIN@ plugin is done in the `gerrit.config`
file. Note that `auth.type` must be set to `OAUTH`.

```
[auth]
  type = OAUTH

[plugin "@PLUGIN@"]
  serverUrl = <URL of the UAA server>
  clientId = "<client id>"
  clientSecret = "<client secret>"
  verifySignatures = true
```

The parameters `clientId` and `clientSecret` must match the name and
password of the Gerrit client as registered with the UAA server above.
The `serverUrl` must point to the UAA server and include the context path,
e.g `http(s)://example.org/uaa`.

Alternatively, re-run `init` to configure the @PLUGIN@ plugin:

```
  java -jar gerrit.war init -d <site>
  [...]

  *** Cloud Foundry UAA OAuth 2.0 Authentication Provider
  ***

  UAA server URL    [http://localhost:8080/uaa]: <URL of the UAA server>
  Client id         [gerrit]: <client id>
  Client secret             : <client secret>
           confirm password : <client secret>
  Verify token signatures [Y/n]?
```

UAA issues so-called [JSON Web Tokens](http://tools.ietf.org/html/rfc7519]),
which include a signature. By default, the @PLUGIN@ plugin will verify
signatures of access tokens it received from UAA. Both HMACSHA256 and
SHA256withRSA signatures are supported given that the underlying Java runtime
provides the necessary ciphers. If that is not the case you might switch off
the verification by setting the parameter `verifySignatures` to `false`.
Note that this is strongly discouraged for security reasons.

If the `auth.gitBasicAuth` parameter is set to `true`, the UAA will be used
to also authenticate also Git-over-HTTP communication.

For Git-over-HTTP communication the plugin accepts passwords and OAuth2
access tokens sent in an `Authorization` header following the `BASIC`
authentication scheme (RFC 2617 section 2). The plugin will pass the
credentials to UAA for verification.


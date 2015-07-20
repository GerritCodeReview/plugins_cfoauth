Cloud Foundry UAA OAuth 2.0 Authentication Provider
===================================================

With this plugin Gerrit can use OAuth2 protocol to authenticate users
accessing Gerrit's Web UI with a
[CloudFoundry User Account and Authentication (UAA)](https://github.com/cloudfoundry/uaa)
server. The `Sign In` link will redirect the user to the UAA login screen.

For Git-over-HTTP communication users still need to generate and use
an HTTP password.

License
-------

Apache License 2.0

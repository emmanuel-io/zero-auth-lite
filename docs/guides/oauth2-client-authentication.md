# OAuth2 Client Authentication

Client authentication depends on the endpoint, registered client type, and
server policy. It is not universally HTTP Basic.

Public clients identify themselves with `client_id` and do not have a client
secret. Authorization-code public clients must use PKCE S256. Confidential
clients authenticate with `client_secret_basic`. They may use
`client_secret_post` when the server-wide `allow_client_secret_post` policy is
enabled. Zero Auth Lite does not currently register an authentication method per
client. Credentials are never accepted in query strings.

Requests that combine Basic and body credentials, provide conflicting client
identifiers, or try to authenticate a public client with a secret are rejected.
The presence of a secret field is significant: an empty `client_secret` is
still a supplied secret and is rejected for a public client. Likewise, empty
body credential fields cannot bypass the prohibition on combining Basic and
body authentication.
Authentication failures return `401 invalid_client` without revealing whether
the identifier or secret was wrong.

The token, revocation, and device authorization endpoints therefore model
Basic authentication as conditional. Introspection always requires an
authenticated confidential client. The `client_credentials` grant is also
confidential-only.

Client confidentiality is immutable after creation. A replacement secret is
returned once, stored as a hash, immediately replaces the previous secret, and
is returned with `Cache-Control: no-store`. Raw secrets must not be logged or
retained after authentication. The authentication boundary passes the resolved
client and authentication method to grant services, so authorization-code and
device flows do not receive or verify the raw secret a second time.

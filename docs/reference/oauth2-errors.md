# OAuth2 Errors

OAuth2 protocol routes translate FastAPI request validation failures into
OAuth2 error responses. They do not return or advertise FastAPI's generic
`422` response. Normal application JSON APIs keep the usual `422` status and
serialize validation failures with the application error envelope.

## Authorization Errors

The authorization endpoint redirects errors only after both the client and its
exact redirect URI are trusted. Unknown clients, inactive clients,
cross-organization clients, malformed redirect URIs, fragments, and unregistered
redirect URIs receive a direct error response and are never redirected.

After the callback is trusted, errors such as `invalid_request`,
`unauthorized_client`, `unsupported_response_type`, and `invalid_scope` are
returned in the redirect query. The original `state` is preserved unchanged.
A denied consent decision redirects with `access_denied`.

## Endpoint Errors

The token endpoint uses `invalid_client`, `invalid_grant`,
`unauthorized_client`, `unsupported_grant_type`, and `invalid_scope` as
appropriate. Device polling additionally uses `authorization_pending`,
`slow_down`, `access_denied`, and `expired_token`.

Missing or invalid UserInfo bearer tokens return `invalid_token` with a
`WWW-Authenticate: Bearer` challenge. A token without `openid` returns
`insufficient_scope` and identifies the required scope.

Token issuance and device-authorization responses include
`Cache-Control: no-store` and `Pragma: no-cache`. Other sensitive responses,
such as a newly issued client secret or UserInfo, are marked `no-store`.
Client authentication failures include a Basic challenge where applicable.
The challenge is emitted only when the client actually attempted HTTP Basic;
body credentials and public-client identification do not claim that Basic was
used.

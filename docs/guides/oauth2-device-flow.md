# OAuth2 Device Flow

A device requests codes with a form POST to
`/oauth2/device_authorization`. A public client supplies `client_id`; a
confidential client uses its registered authentication method. Supplying a
secret for a public client is rejected instead of being ignored. The response
always includes a verification URI, complete verification URI, positive expiry,
and positive polling interval, with no-store/no-cache headers.

This implementation keeps Device Code as an OAuth2 authorization flow. It
rejects the `openid` scope with `invalid_scope` and therefore does not issue an
OIDC ID token through this grant. Zero Auth Lite demonstrates OIDC identity through
the Authorization Code flow instead.

With the built-in UI enabled, `GET /oauth2/device/verify` authenticates the
browser when necessary and displays the device page. The user approves or
denies a pending request with a form POST to the same path. The POST requires
the browser session plus configured CSRF header or hidden-form protection.
These presentation routes remain visible in the application OpenAPI document
under the device-flow tag, but they are built-in HTML adapters rather than
OAuth2 protocol endpoints. Device authorization and token polling remain the
protocol endpoints.

The current server does not accept an external verification URL. Enabling the
device-code grant while disabling the built-in UI is therefore rejected during
settings validation, before a client can receive an unusable verification URI.

The decision is organization-bound and one-time. Invalid, expired, or already
completed codes return a `400` HTML response; another user cannot overwrite a
completed decision.

The device polls `/oauth2/token` with the device-code grant. Polling before a
decision returns `authorization_pending`. Polling too quickly returns
`slow_down` and increases the required interval by five seconds. Denial returns
`access_denied`, expiry returns `expired_token`, and an approved device code
can issue tokens only once.

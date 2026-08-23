# External Authentication UI

Use an external authentication UI when another frontend should render login,
logout, registration, verification, invitation, and password-recovery screens.
Zero Auth Lite still owns credentials, browser sessions, identity state, CSRF
policy, OAuth2 transactions, and all authorization decisions.

## Configure The Transport

Set:

```text
ZA_UI__AUTHENTICATION=external
ZA_UI__EXTERNAL_LOGIN_URL=https://frontend.example/login
ZA_AUTH__EMAIL__FRONTEND_BASE_URL=https://frontend.example
```

The first setting selects the versioned JSON routes. The second is the browser
destination used when OAuth2 requires user authentication. The email frontend
origin determines where verification, invitation, and recovery links are sent.
See the [startup route matrix](../reference/routes.md#startup-route-matrix) for
the exact mounted surfaces.

## Authenticate A Browser

1. Call `GET /api/v1/sessions/csrf`, retain the pre-session cookie, and read the
   configured CSRF value from its response header or cookie.
2. Submit the credentials to `POST /api/v1/sessions/login` with the CSRF value
   and an accepted `Origin` or `Referer`.
3. Retain the resulting opaque `HttpOnly` session cookie and session-bound CSRF
   state. The frontend does not receive the password hash or stored session.
4. Use `/api/v1/auth/*` for the JSON identity workflows exposed by the active
   startup settings.

## Resume OAuth2 Interaction

After validating an Authorization Code request, Zero Auth Lite redirects an
unauthenticated browser to `ui.external_login_url` with an opaque
`transaction_id`. The frontend authenticates the browser through the JSON
session contract, then navigates to:

```text
/consent?transaction_id=<opaque value>
```

For Device Code, the login URL receives `device_code`; after authentication,
resume at:

```text
/oauth2/device/verify?user_code=<opaque value>
```

Treat these values only as opaque continuation identifiers. Do not decode them,
turn them into arbitrary redirects, or allow a caller to replace the server
paths. Zero Auth Lite binds and validates the underlying transaction before consent
or device approval.

The external frontend authenticates the user; it does not issue authorization
codes or tokens. OAuth2 authorization and token issuance remain on the
canonical server.

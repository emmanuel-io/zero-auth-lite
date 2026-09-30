# External Authentication UI

Use an external frontend when another application should render identity or
OAuth2 screens. Zero Auth Lite remains responsible for credentials, browser
sessions, CSRF, organization policy, OAuth2 state, decisions, codes, and
tokens. The frontend presents server-owned state; it does not become an
authorization server.

## Configure Independent Surfaces

The recommended mixed profile keeps the trusted management login built in and
delegates complete OAuth2 interaction to the frontend:

```text
ZA_API__INTERACTIVE_AUTH_ROUTES_ENABLED=true
ZA_UI__IDENTITY_WORKFLOW_MODE=external
ZA_UI__MANAGEMENT_AUTHENTICATION=builtin
ZA_UI__OAUTH2_INTERACTION=external
ZA_UI__URLS__VERIFICATION=https://frontend.example/verify-email
ZA_UI__URLS__PASSWORD_RESET=https://frontend.example/reset-password
ZA_UI__URLS__INVITATION=https://frontend.example/accept-invite
ZA_UI__URLS__AUTHORIZATION_INTERACTION=https://frontend.example/oauth2/authorize
ZA_UI__URLS__DEVICE_INTERACTION=https://frontend.example/oauth2/device
ZA_CORS__ALLOWED_ORIGINS='["https://frontend.example"]'
ZA_BROWSER_SESSION__CSRF__TRUSTED_ORIGINS='["https://frontend.example"]'
```

`api.interactive_auth_routes_enabled=true` mounts `/api/v1/auth/*` and, when sessions
are enabled, `/api/v1/sessions/*`. The setting defaults to true and is independent
from presentation. Setting `ui.identity_workflow_mode=external` removes the equivalent
HTML forms; keeping `builtin` allows the HTML and JSON adapters to coexist. Neither
setting chooses management or OAuth2 navigation.

Use `ui.identity_workflow_mode=disabled` together with
`api.interactive_auth_routes_enabled=false` when neither this server nor an external
frontend should expose identity workflows. This is a machine-only topology: it
requires browser sessions, refresh tokens, and self-registration to be disabled
so no user can start a workflow whose notification link has no consumer.

To make management authentication external too, set:

```text
ZA_UI__MANAGEMENT_AUTHENTICATION=external
ZA_UI__URLS__LOGIN=https://frontend.example/login
ZA_UI__URLS__LOGOUT=https://frontend.example/logout
```

External management authentication requires the interactive authentication API routes. A
management page without a session redirects to `ui.urls.login` with a validated
internal `return_url`; Sign out navigates to `ui.urls.logout`. Any valid
session created by Zero Auth Lite is accepted by management regardless of which
frontend initiated it.

When built-in identity-workflow forms are combined with external management
authentication, a completed registration, verification, invitation, or password
reset also returns to `ui.urls.login`. The server adds a `notice` query
parameter containing a fixed presentation code such as `email-verified`. Treat
that value as an opaque code selected by the server, not as text to render
verbatim.

The notification service uses `ui.urls.verification`, `ui.urls.invitation`, and
`ui.urls.password_reset` directly. The server appends only the opaque `token`
query parameter.

## Configure The Browser Topology

When the frontend and Zero Auth Lite use different origins, add the frontend's
exact origin to both `cors.allowed_origins` and
`browser_session.csrf.trusted_origins`. Browser requests must use the Fetch
`credentials: "include"` option so the browser accepts and sends the server's
cookies. CORS permits the browser to read an accepted response; it does not
replace CSRF origin and token validation.

A frontend served through the same origin as Zero Auth Lite does not need CORS
and may set `cors.allowed_origins` to an empty collection. Host-only session and
CSRF cookies remain sufficient because requests still target the server origin.

If the frontend is cross-site rather than merely cross-origin, the browser will
not attach the default `SameSite=lax` cookies to Fetch requests. That topology
requires `SameSite=none` and `Secure` for both session and CSRF cookies. Review
their `Domain` values as well; use a shared cookie domain only when browser-side
CSRF token exposure actually requires it. The default header exposure keeps the
CSRF token readable without sharing the CSRF cookie with frontend JavaScript.

## Authenticate A Browser

1. Call `GET /api/v1/sessions/csrf` and retain the pre-session cookie.
2. Submit credentials to `POST /api/v1/sessions/login` with the exposed CSRF
   header and an accepted `Origin` or `Referer`.
3. Retain the opaque `HttpOnly` session cookie and session-bound CSRF state.
4. Use `/api/v1/auth/*` for enabled JSON identity workflows.

To log out, obtain current CSRF state and call
`POST /api/v1/sessions/logout`. Merely navigating away leaves the server
session active.

## Authorization Code Interaction

With `ui.oauth2_interaction=external`, `/oauth2/authorize` redirects to:

```text
https://frontend.example/oauth2/authorize?transaction_id=<opaque value>
```

After establishing a session, the frontend calls:

- `POST /api/v1/oauth2/authorization-interactions/{transaction_id}` with the
  session cookie, CSRF header, and accepted origin to bind and continue the
  transaction. The operation is intentionally not a `GET`: it may consume the
  single-use interaction and issue an authorization code when consent is not
  required. The result either requests consent with the safe client name and
  scopes, or returns a validated OAuth2 `redirect_url`.
- `POST /api/v1/oauth2/authorization-interactions/{transaction_id}/decision`
  with `{"decision":"approve"}` or `{"decision":"deny"}`, the session cookie,
  CSRF header, and accepted origin. The returned `redirect_url` is the only URL
  the frontend should follow.

Transactions are opaque, expire, bind to one user and organization, and are
consumed once. The browser never supplies a client callback URL to the
decision endpoint.

## Device Code Interaction

The Device Authorization response publishes `ui.urls.device_interaction` as
`verification_uri` and adds `user_code` to
`verification_uri_complete`. After login, the frontend calls:

- `GET /api/v1/oauth2/device-interactions/{user_code}` for safe client and
  scope details;
- `POST /api/v1/oauth2/device-interactions/{user_code}/decision` with the same
  decision body and CSRF protection. Success returns `204 No Content`.

All interaction responses use `Cache-Control: no-store`. Missing, expired,
consumed, or foreign interactions return the same
`400 OAUTH2_INTERACTION_INVALID` response so their existence is not disclosed.
No client secret, token, database identifier, or unvalidated redirect is
returned by these APIs.

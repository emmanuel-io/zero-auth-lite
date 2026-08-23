# Built-In Authentication UI

Zero Auth Lite uses its built-in authentication UI by default. It provides small,
server-rendered pages for login, logout, registration, email verification,
password recovery, and invitation acceptance. The canonical server still owns
credentials, browser sessions, identity state, CSRF policy, OAuth2
transactions, and every authorization decision.

Use these pages for the runnable reference server or whenever a separate
frontend is unnecessary. To render the same workflows in another application,
use the [external authentication UI](external-authentication-ui.md) contract
instead.

## Configure The Built-In UI

The default configuration includes:

```text
ZA_UI__AUTHENTICATION=builtin
ZA_UI__OAUTH2_INTERACTION=builtin
ZA_SESSION__ENABLED=true
```

`ui.authentication` selects the built-in authentication and identity-workflow
forms. `ui.oauth2_interaction` independently controls the OAuth2 consent and
Device Code pages. Browser login and logout also require sessions. See the
[startup route matrix](../reference/routes.md#startup-route-matrix) for the
exact surfaces mounted by each combination.

## Available Pages

The built-in authentication transport uses ordinary HTML forms and works
without client-side JavaScript:

| Path | Purpose |
| --- | --- |
| `/` | Open the server landing page. |
| `/login` | Authenticate credentials and create a browser session. |
| `/logout` | Revoke the current browser session. |
| `/register` | Create an organization and its initial user when registration is enabled. |
| `/resend-verification` | Request another verification email when registration is enabled. |
| `/forgot-password` | Request a password-reset email. |
| `/verify-email` | Confirm an email address using a single-use workflow token. |
| `/reset-password` | Set a new password using a single-use workflow token. |
| `/accept-invite` | Accept an invitation and set the first password. |

The [route reference](../reference/routes.md#built-in-authentication-transport)
lists the supported methods and feature conditions.

## Authenticate A Browser

1. The browser opens `GET /login`. Zero Auth Lite renders the form and issues
   anonymous CSRF state.
2. The browser submits the email, password, and hidden CSRF value to
   `POST /login` from an accepted origin.
3. Zero Auth Lite verifies the credentials, creates server-side session state, and
   gives the browser an opaque `HttpOnly` session cookie.
4. Zero Auth Lite redirects the browser to the server-owned continuation or a
   configured post-login destination.

The browser never receives the password hash or stored session. Login uses the
same authentication and session services as the external JSON transport; only
the browser-facing adapter differs. The
[browser sessions and CSRF](sessions-and-csrf.md) guide explains cookie
lifetime, session renewal, and revocation.

## Continue OAuth2 Interactions

An unauthenticated Authorization Code request redirects the browser to
`/login` with an opaque `transaction_id`. After login, Zero Auth Lite resumes the
validated transaction at `/consent`. The client receives an authorization code
only after the server has authenticated the user and completed any required
consent decision. The client never sees the user's password.

For Device Code, the login page carries an opaque device continuation. After
authentication, Zero Auth Lite returns the browser to `/oauth2/device/verify`, where
the user approves or denies the request.

The continuation values identify server-side state. They are not access
tokens, redirect destinations, or data for the browser to decode. When login is
not continuing a protocol interaction, Zero Auth Lite accepts only a validated
same-origin `return_url`, then falls back to `ZA_DEFAULT_REDIRECT_URL`
or `/`.

## Identity Workflow Security

Anonymous forms use pre-session CSRF state. Authenticated forms use CSRF state
bound to the browser session. State-changing submissions also require an
accepted browser origin.

Verification, password-reset, and invitation links carry short-lived,
single-use workflow tokens. These tokens authorize only their named identity
operation; they are not OAuth2 access tokens and cannot call protected APIs.
Successful form submissions use redirects so refreshing the resulting page
does not repeat the credential or token mutation.

The built-in UI is deliberately a small authentication surface, not a general
account-management application. Profile, session, authorization, organization,
and operator operations remain in the versioned `/api/v1` API.

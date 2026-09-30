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
ZA_API__INTERACTIVE_AUTH_ROUTES_ENABLED=true
ZA_UI__IDENTITY_WORKFLOW_MODE=builtin
ZA_UI__MANAGEMENT_AUTHENTICATION=builtin
ZA_UI__OAUTH2_INTERACTION=builtin
ZA_UI__ORGANIZATION_ADMIN_ENABLED=true
ZA_UI__OPERATOR_ENABLED=true
ZA_BROWSER_SESSION__ENABLED=true
```

The `builtin` value for `ui.identity_workflow_mode` selects the server-rendered
identity-workflow forms. The independently enabled
`api.interactive_auth_routes_enabled` keeps the JSON adapters available for API
clients. `ui.management_authentication` selects `/login` and `/logout` for
management, while `ui.oauth2_interaction` independently controls OAuth2 login,
consent, and Device Code pages. Browser login and logout require sessions. See the
[startup route matrix](../reference/routes.md#startup-route-matrix) for the
exact surfaces mounted by each combination.

The administration toggles are independent from the authentication
presentation mode. An external login application may establish the canonical
browser session and then return the user to `/management`,
`/management/organization`, or `/management/operator`.

## Available Pages

The built-in authentication transport uses ordinary HTML forms and works
without client-side JavaScript:

| Path | Purpose |
| --- | --- |
| `/` | Open the server landing page. |
| `/management` | Open the authenticated management dashboard. |
| `/management/account` | Read and update the authenticated user's profile. |
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

Anonymous authentication workflows use a compact, focused page shell. After
login, `/` redirects to the role-aware dashboard at `/management`.
Authenticated management pages share a responsive application header. The
header always exposes Home, Account, and
Sign out, then adds Organization and Operator destinations only when the
current user has that authority. Its mobile menu uses native HTML and CSS, so
navigation remains available without JavaScript.

The account page is self-service rather than administration. Every authenticated
browser user can update their email, first name, and last name regardless of
organization-admin or operator authority. A changed email remains pending until
the user completes email verification; the current verified address continues to
identify the account in the meantime.
Unlike the authentication workflow pages, `/management/account` remains mounted
when external management authentication is selected, as long as browser
sessions are enabled.

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
`/login` with an opaque `transaction_id`. After login, Zero Auth Lite resumes
the validated transaction at `/consent`. This browser navigation binds the
transaction and consumes it immediately when explicit consent is not required.
The client receives an authorization code only after the server has authenticated
the user and completed any required consent decision. The client never sees the
user's password.

For Device Code, the login page carries the `user_code` shown to the user. It
never carries the separate `device_code` secret held by the client. After
authentication, Zero Auth Lite returns the browser to `/oauth2/device/verify`,
where the user approves or denies the request.

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

## Administer The Server In A Browser

After login, every user can open `/management` and `/management/account`.
Current organization administrators can also open `/management/organization`,
and server operators can open `/management/operator`. A user holding both
roles sees both administration links.
These htmx-enhanced pages are a presentation layer over the existing identity,
session, and OAuth2 services; the stable programmatic contracts remain under
`/api/v1/organization` and `/api/v1/server`.

Authentication and authorization stay separate. The session identifies the
user, then every request reloads the user's current roles before granting the
organization or operator action. OAuth2 scopes do not grant access to these
browser pages, and enabling or disabling a browser UI does not change API
permissions.

All mutations carry session-bound CSRF proof. Deletion, revocation, credential
rotation, and global cleanup also require visible confirmation. htmx updates
list fragments when JavaScript is available; ordinary server-rendered forms use
POST/Redirect/GET as the fallback.

The bundled htmx asset is loaded from the server itself. The browser Content
Security Policy permits scripts and asynchronous connections only to the same
origin through `script-src 'self'` and `connect-src 'self'`; no deployment host
is embedded in the policy. Validation and application failures on these pages
are rendered as HTML, including fragment responses for htmx requests.

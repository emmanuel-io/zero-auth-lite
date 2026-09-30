# Settings Reference

This page is the canonical inventory of environment variables, configuration
keys, defaults, and constraints. Guides repeat a setting only when it is needed
to explain a concrete workflow or operational decision.

Zero Auth Lite loads one immutable Pydantic settings snapshot when `create_app()` is
called. It reads the optional `zero-auth-lite.toml` file from the working directory;
`ZA_CONFIG_FILE` selects another file and requires that file to exist. TOML
tables mirror the settings model, so `browser_session.csrf.header_name` is written as
`header_name` under `[browser_session.csrf]`.

Environment overrides use the `ZA_` prefix and `__` between nested sections.
For example, `browser_session.csrf.header_name` becomes
`ZA_BROWSER_SESSION__CSRF__HEADER_NAME`. Values are resolved in this order: explicit
Python arguments, environment overrides, TOML, then model defaults. TOML uses
native arrays, tables, booleans, integers, and floats; environment collections
remain JSON-encoded strings.

Each feature model owns its canonical defaults. Setting one nested environment
variable changes only that field; omitted values continue to use the defaults
documented for the same section.

Changing the TOML file, environment variables, or `app.state.settings` after
construction does not recompose routes. Restart the server to apply changes.

`ZA_CONFIG_FILE` controls configuration loading and is not a model field. An
invalid TOML document, an unknown setting, or a missing explicitly selected
file fails startup.

## Server And Infrastructure

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `ZA_APP__ENVIRONMENT` | `development` | Use `deployment` to reject local secrets and missing baseline security controls. |
| `ZA_APP__LOG_LEVEL` | `INFO` | Application log threshold for the console (`stdout`) handler. Zero Auth Lite does not configure syslog directly. |
| `ZA_APP__TRUSTED_HOSTS` | empty | Hosts accepted by trusted-host middleware. Deployment mode requires a non-empty restrictive list and rejects `*`. |
| `ZA_APP__TRUSTED_PROXY_IPS` | empty | Valid IP addresses or CIDR networks trusted when resolving source addresses. Deployment mode rejects malformed entries. |
| `ZA_DEFAULT_REDIRECT_URL` | unset | Trusted application URL used after a standalone interactive login when no protocol flow or internal return target takes priority. Deployment mode requires HTTPS and rejects local-only hosts. |
| `ZA_DB_PATH` | `./data/zero-auth-lite.db` | Filesystem path to the canonical SQLite database. Alembic creates missing parent directories before applying migrations. |
| `ZA_DB_ECHO` | `false` | Emit SQLAlchemy statements for local debugging with bound parameter values hidden. |
| `ZA_RUNTIME_DIR` | `/tmp/zero-auth-lite` | Ephemeral process state shared by workers on one host. |
| `ZA_CORS__ALLOWED_ORIGINS` | local origins | JSON array of exact browser origins accepted by CORS. |
| `ZA_CORS__ALLOW_CREDENTIALS` | `true` | Allow browsers to include credentials on accepted cross-origin requests. |
| `ZA_CORS__ALLOW_METHODS` | `["*"]` | JSON array of HTTP methods accepted by CORS preflight checks. |
| `ZA_CORS__ALLOW_HEADERS` | `["*"]` | JSON array of request headers accepted by CORS preflight checks. |
| `ZA_CORS__EXPOSE_HEADERS` | `["X-CSRF-Token","X-Request-Id"]` | Response headers browser JavaScript may read. |

`ZA_CORS__ALLOWED_ORIGINS` is always an explicit collection, even for one origin. For
example: `ZA_CORS__ALLOWED_ORIGINS='["https://app.example"]'`. A bare
string is rejected so the middleware cannot interpret it using substring
membership. Set it to `[]` for a same-origin server or a server without
cross-origin browser clients; an empty collection leaves CORS middleware
unmounted.

SQLAlchemy is the canonical persistence baseline. Browser sessions, OAuth2
state, authorization codes, identity, organization, client, and durable lifecycle
state remain in SQL.

`ZA_DB_PATH` is deliberately a SQLite file path rather than an arbitrary
SQLAlchemy URL. Other database engines and remote database URLs are not part of
the canonical server contract.

`ZA_RUNTIME_DIR` contains disposable process coordination state, not
database or application data. A managed Linux service can set it to
`/run/zero-auth-lite` after creating that directory with the service user's
ownership. Keep persistent state in the configured database or data volume
instead.

The local Compose stack pins Caddy to `172.30.0.10` and sets
`ZA_APP__TRUSTED_PROXY_IPS` to `172.30.0.10/32`. Keep this trust list empty when
the server has no reverse proxy or receives traffic directly. In other
topologies, list only proxy addresses you control; trusting a broad network
lets other peers forge the source metadata recorded with browser sessions
through forwarded headers. The canonical server commands disable Uvicorn
proxy-header rewriting so this setting is the only forwarded-address trust
boundary. Keep that server-layer rewriting disabled with custom launchers.

`development` keeps the committed local defaults convenient for the direct and
Compose examples. Set `ZA_APP__ENVIRONMENT=deployment` for any deployed
server. That mode fails before startup while a checked-in session, OAuth2,
workflow-token, or signing secret remains in use by an enabled or reachable
capability. It also requires explicit trusted hosts, secure session cookies when
sessions are enabled, and a non-local browser topology. When identity workflows
are reachable, it requires a non-local workflow topology and mail delivery
because verification, invitation, and password-recovery workflows depend on it.
`localhost`, subdomains ending in `.localhost`, and loopback IP addresses are
rejected in issuer, email, cookie-domain, CORS, and CSRF settings. This
validation is a minimum safety boundary, not a complete production-readiness
claim.

## Application API

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `ZA_API__INTERACTIVE_AUTH_ROUTES_ENABLED` | `true` | Mount the interactive JSON adapters for sessions, identity workflows, and external OAuth2 interactions under `/api/v1`; does not control `/me`, `/organization`, or `/server`. |

These interactive JSON adapters are independent from presentation. Their
default allows API clients to use the identity workflows while the built-in
forms remain available. Disable them only when the deployment exclusively uses
server-rendered workflows. External identity, management-authentication, or
OAuth2-interaction presentation requires these adapters. The authenticated
`/me`, `/organization`, and `/server` APIs remain mounted either way.

## Browser Presentation And Navigation

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `ZA_UI__IDENTITY_WORKFLOW_MODE` | `builtin` | Select `builtin`, `external`, or `disabled` identity-workflow presentation. |
| `ZA_UI__MANAGEMENT_AUTHENTICATION` | `builtin` | Select built-in or external login/logout navigation for management pages. |
| `ZA_UI__OAUTH2_INTERACTION` | `builtin` | Select `builtin`, `external`, or `disabled` OAuth2 interaction presentation. |
| `ZA_UI__URLS__LOGIN` | `/login` | Login destination used by management navigation and workflow completion. |
| `ZA_UI__URLS__LOGOUT` | `/logout` | Logout destination used by the Management UI. |
| `ZA_UI__URLS__VERIFICATION` | local built-in verification URL | Exact destination placed in verification and email-change notifications. |
| `ZA_UI__URLS__PASSWORD_RESET` | local built-in reset URL | Exact destination placed in password-reset notifications. |
| `ZA_UI__URLS__INVITATION` | local built-in invitation URL | Exact destination placed in invitation notifications. |
| `ZA_UI__URLS__AUTHORIZATION_INTERACTION` | `/login` | Browser entry point for Authorization Code interaction. |
| `ZA_UI__URLS__AUTHORIZATION_CONSENT` | `/consent` | Built-in consent destination used after login. |
| `ZA_UI__URLS__DEVICE_INTERACTION` | local built-in device URL | Verification URI returned to Device Code clients. |
| `ZA_UI__ORGANIZATION_ADMIN_ENABLED` | `true` | Mount organization administration under `/management/organization`. |
| `ZA_UI__OPERATOR_ENABLED` | `true` | Mount server-operator administration under `/management/operator`. |

The three presentation modes are independent from each other and from the JSON
identity-workflow transport.
Setting identity-workflow presentation to `disabled` removes the built-in
pages without claiming that an external frontend owns them. The JSON transport
remains an independent decision. When that transport stays enabled, headless
JSON clients own workflow completion and the verification, password-reset, and
invitation destinations must be absolute HTTP(S) URLs. Self-registration
requires at least one of these two transports.
Built-in management mounts `/login` and `/logout`; external management requires
absolute login and logout URLs and `api.interactive_auth_routes_enabled=true`.
External OAuth2 interaction requires the interactive authentication API routes only while
Authorization Code or Device Code is enabled, plus an absolute interaction URL
for each enabled interactive grant. Setting the
interaction mode to `disabled` denies Authorization Code requests that need
login or consent, and is invalid while Device Code is enabled.
The two administration toggles control HTML presentation only. They never
remove `/api/v1/organization` or `/api/v1/server`. These APIs remain mounted
when `browser_session.enabled=false` and use the Bearer authentication supported by
each route; only the corresponding management HTML is omitted.
Every component reads these configured URLs directly. Built-in modes validate
absolute workflow and device URLs against `browser_session.csrf.public_origin`
as well as their canonical paths, so server-issued tokens cannot be sent to a
different origin. External modes accept their explicitly configured frontend
origins. External presentation and headless JSON workflows require absolute
HTTP(S) URLs. Credentials, query strings, and fragments are rejected
because the server owns the appended `token`, `transaction_id`, `user_code`,
`return_url`, and `notice` values.
Deployment mode also requires HTTPS and rejects local-only hosts.
The canonical [startup route matrix](routes.md#startup-route-matrix) lists the
resulting surfaces and invalid combinations. See the
[built-in authentication UI](../guides/builtin-authentication-ui.md) for the
default server-rendered flow. In external OAuth2 mode, the server adds only an
opaque transaction or device continuation identifier to the corresponding
configured URL; the Management UI independently uses its login and logout
destinations. See
the [external authentication UI](../guides/external-authentication-ui.md)
contract for the complete resume flow.

Standalone login redirects resume an OAuth2 or device interaction first, then
accept one validated same-origin `return_url`, then use
`ZA_DEFAULT_REDIRECT_URL`, and finally fall back to `/`. Request values
containing a scheme, host, protocol-relative path, backslash, fragment, or
encoded equivalent are never used as redirect destinations.

## Browser Sessions

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `ZA_BROWSER_SESSION__ENABLED` | `true` | Mount browser-session routes and services. |
| `ZA_BROWSER_SESSION__COOKIE_DOMAIN` | `zero-auth-lite.localhost` | Domain attribute shared by the browser-session cookie. Use an empty value for a host-only cookie. |
| `ZA_BROWSER_SESSION__COOKIE_NAME` | `sessionid` | Opaque browser-session cookie name. |
| `ZA_BROWSER_SESSION__COOKIE_SECURE` | `true` | Send the session cookie only over HTTPS. |
| `ZA_BROWSER_SESSION__COOKIE_SAME_SITE` | `lax` | Browser cross-site cookie policy. |
| `ZA_BROWSER_SESSION__TTL_SECONDS` | `28800` | Sliding session lifetime in seconds. |
| `ZA_BROWSER_SESSION__ABSOLUTE_TTL_SECONDS` | `604800` | Seven-day maximum lifetime regardless of activity. |
| `ZA_BROWSER_SESSION__CLEANUP_BATCH_SIZE` | `100` | Maximum expired or revoked sessions deleted by one cleanup operation. |
| `ZA_BROWSER_SESSION__CLEANUP_INTERVAL_SECONDS` | `3600` | Delay between automatic browser-session cleanup runs. |
| `ZA_BROWSER_SESSION__SLIDE_SECONDS` | `1800` | Remaining-lifetime threshold for extending SQL expiry and age threshold for a standalone persisted `last_seen_at` update. |
| `ZA_BROWSER_SESSION__MAX_SESSIONS_PER_USER` | `10` | Concurrent valid-session limit per user. |
| `ZA_BROWSER_SESSION__HASH_SECRET` | development value | Root HMAC secret for session lookup, login-identifier, source-IP, and user-agent hashes. |

`ttl_seconds` cannot exceed `absolute_ttl_seconds`, and `slide_seconds` cannot
exceed `ttl_seconds`. Cookies for an existing session use its effective
remaining SQL lifetime rather than restarting the full configured TTL on every
response. With the defaults, activity inside the sliding window renews the
eight-hour session up to the seven-day absolute limit. `slide_seconds` also
limits standalone `last_seen_at` persistence between expiry extensions.
Inactive-session cleanup deletes at most `cleanup_batch_size` expired or revoked
rows per run. The worker repeats it automatically; an administrative request
may also trigger one batch. The explicit `scope=all` operation
remains intentionally unbounded.

Session lookup, login identifiers, source IP addresses, and user agents use
separate HMAC domains derived from `hash_secret`, so their digests cannot be
correlated across contexts. Changing this secret invalidates every browser
session and requires users to sign in again.
Expired rows awaiting cleanup do not count toward `max_sessions_per_user` and
cannot displace an older session that remains valid.
Replace the development hash secret in every deployment.
Cookie names must use HTTP token characters. The session cookie name must differ
from both the configured CSRF cookie name and its `-form` variant used by
anonymous server-rendered forms; ambiguous names are rejected at startup.

## CSRF

CSRF settings are nested under `browser_session.csrf`.

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `ZA_BROWSER_SESSION__CSRF__PATTERN` | `synchronizer_token` | CSRF validation pattern. |
| `ZA_BROWSER_SESSION__CSRF__ORIGIN_CHECK_ENABLED` | `true` | Validate browser request origins. |
| `ZA_BROWSER_SESSION__CSRF__PUBLIC_ORIGIN` | local auth origin | External browser origin. |
| `ZA_BROWSER_SESSION__CSRF__TRUSTED_ORIGINS` | local origins | Additional accepted origins. |
| `ZA_BROWSER_SESSION__CSRF__HEADER_NAME` | `X-CSRF-Token` | Request and exposure header. |
| `ZA_BROWSER_SESSION__CSRF__EXPOSE_TOKEN` | `header` | Expose CSRF state through `header` or a readable `cookie`. |
| `ZA_BROWSER_SESSION__CSRF__COOKIE_DOMAIN` | `zero-auth-lite.localhost` | Domain attribute shared by the CSRF cookie. Use an empty value for a host-only cookie. |
| `ZA_BROWSER_SESSION__CSRF__COOKIE_NAME` | `csrftoken` | CSRF cookie name when used. |
| `ZA_BROWSER_SESSION__CSRF__COOKIE_SECURE` | `true` | Send the CSRF cookie only over HTTPS. |
| `ZA_BROWSER_SESSION__CSRF__COOKIE_SAME_SITE` | `lax` | Browser cross-site policy for the CSRF cookie. |
| `ZA_BROWSER_SESSION__CSRF__TTL_SECONDS` | `28800` | Stateless pre-session CSRF cookie lifetime. Authenticated CSRF cookies follow the browser-session lifetime. |

In `deployment` mode, the public CSRF origin and OAuth2 issuer hosts must be
accepted by `app.trusted_hosts`. Non-empty session and CSRF cookie domains must
be valid DNS domains that cover the public CSRF origin host. CORS and trusted
CSRF origins may still name a separate frontend host.
When CORS middleware is mounted and sessions are enabled, the configured CSRF
header is automatically allowed. It is also exposed when CSRF exposure uses the
header transport.
In `deployment` mode, startup requires both the session and CSRF cookies to be
`Secure`, rejects local-only cookie domains, validates configured CORS origins,
and requires CSRF origins to be exact, non-local absolute HTTPS origins.
Separate frontend and identity-provider origins remain valid configurations.

## OAuth2 And OpenID Connect

| Environment variable | Canonical default | Purpose |
| --- | --- | --- |
| `ZA_OAUTH2__AUTHORIZATION_CODE_ENABLED` | `true` | Enable authorization code with PKCE. |
| `ZA_OAUTH2__CLEANUP_INTERVAL_SECONDS` | `3600` | Interval used by the dedicated OAuth2 cleanup worker. |
| `ZA_OAUTH2__CLEANUP_BATCH_SIZE` | `100` | Maximum expired rows deleted from each OAuth2 table per cleanup transaction. |
| `ZA_OAUTH2__REFRESH_TOKEN_ENABLED` | `true` | Enable refresh-token exchange and rotation. |
| `ZA_OAUTH2__CLIENT_CREDENTIALS_ENABLED` | `true` | Enable machine-to-machine tokens. |
| `ZA_OAUTH2__DEVICE_CODE_ENABLED` | `true` | Enable device authorization and verification. |
| `ZA_OAUTH2__OIDC_ENABLED` | `true` | Enable the OpenID Connect identity layer. |
| `ZA_OAUTH2__JWKS_ENABLED` | `true` | Publish public signing keys. |
| `ZA_OAUTH2__ISSUER` | local HTTPS auth origin | Exact public issuer identifier. |
| `ZA_OAUTH2__ACCESS_TOKEN_AUDIENCE` | `zero-auth-lite-example-api` | Intended access-token audience. |
| `ZA_OAUTH2__SIGNING_KEY_ID` | `local-dev-key` | Current signing key identifier. |
| `ZA_OAUTH2__SIGNING_PRIVATE_KEY_B64` | development key | Base64-encoded raw 32-byte Ed25519 private signing key. |
| `ZA_OAUTH2__SIGNING_PUBLIC_KEY_B64` | development key | Base64-encoded raw 32-byte Ed25519 public verification key matching the private key. |
| `ZA_OAUTH2__PREVIOUS_PUBLIC_KEYS` | `[]` | JSON array of retained `{kid, signing_public_key_b64}` verification keys during rotation. |
| `ZA_OAUTH2__AUTHORIZATION_CODE_HASH_SECRET` | development value | HMAC secret used to hash authorization codes and browser authorization transactions. |
| `ZA_OAUTH2__TOKEN_HASH_SECRET` | development value | HMAC secret used for persisted access, refresh, and device-token lookups. |
| `ZA_OAUTH2__AUTHORIZATION_CODE_TTL_SECONDS` | `300` | Authorization-code and browser authorization-transaction lifetime. |
| `ZA_OAUTH2__ACCESS_TOKEN_LIFETIME_SECONDS` | `900` | Access-token lifetime. |
| `ZA_OAUTH2__ID_TOKEN_LIFETIME_SECONDS` | `900` | OpenID Connect ID-token lifetime. |
| `ZA_OAUTH2__REFRESH_TOKEN_LIFETIME_SECONDS` | `2592000` | Absolute refresh-token family lifetime, measured from initial issuance. Rotation does not extend it. |
| `ZA_OAUTH2__DEVICE_CODE_LIFETIME_SECONDS` | `1800` | Device authorization lifetime. |
| `ZA_OAUTH2__DEVICE_CODE_INTERVAL_SECONDS` | `5` | Initial minimum polling interval returned to a device client. |
| `ZA_OAUTH2__DEVICE_CODE_CREATE_ATTEMPTS` | `5` | Maximum attempts to generate a collision-free device user code. |
| `ZA_OAUTH2__ALLOW_CLIENT_SECRET_POST` | `true` | Permit body-based confidential-client credentials. |

OIDC requires authorization code, JWKS publication, a key ID, and browser
sessions. Authorization code and device verification also require browser
sessions. Device verification requires either the built-in or external OAuth2
interaction mode. External interaction additionally requires the browser JSON
transport while an interactive grant is enabled, plus absolute
`ZA_UI__URLS__AUTHORIZATION_INTERACTION` and
`ZA_UI__URLS__DEVICE_INTERACTION` values for the corresponding enabled grants.
An inert external interaction selection does not constrain a non-interactive
OAuth2 profile. Settings validation rejects invalid combinations before startup.

The issuer must be an absolute HTTP(S) URL with a valid hostname and optional
numeric port, without user information, a query string, or a fragment. In
`deployment` mode it must additionally use HTTPS and a non-local hostname.

Protocol inputs have explicit server limits before they reach persistence.
Client IDs and redirect URIs follow their registration limits; scope lists,
`state`, and `nonce` are limited to 512 characters, and opaque token-like
values are limited to 1024 characters. Requests exceeding these limits receive
OAuth2 protocol errors rather than framework `422` responses.

There is no OAuth2 master switch. The OAuth2/OIDC surface is mounted whenever
at least one grant or JWKS publication is enabled. Disable all grants, OIDC,
and JWKS to remove the complete protocol surface. Application-owned OAuth2
client and token-session administration routes require at
least one enabled grant; JWKS publication alone does not mount them.

A machine-to-machine deployment may disable browser sessions only after also
disabling self-registration, authorization code, device code, and OIDC. Startup
rejects `browser_session.enabled=false` together with `identity_workflow.registration_enabled=true`
because that combination would let a person create an identity without leaving
an authentication mechanism for that identity. The canonical machine profile
also disables Refresh Token because a new `client_credentials`-only installation
has no user grant that can originate a refresh-token family. Refresh Token is
valid only when Authorization Code or Device Code is also enabled; it cannot be
used as a standalone transition mode. Revocation, introspection, OAuth2
metadata, JWKS, and client administration routes remain available. OAuth2
client administration still requires a user-backed operator; use the local
[machine-client provisioning command](../operations/oauth2-client-provisioning.md)
when the deployment has no browser authentication. The separate explicit-
organization session-revocation route can be called by an authorized machine
client as described in the [route reference](routes.md#server-control-plane-administration).

The canonical server rejects a configuration that disables browser sessions
without leaving an OAuth2 grant enabled. JWKS publication alone is not an
authentication mechanism. In `deployment` mode, an enabled OAuth2 surface also
requires an HTTPS issuer.

Signing and hashing secrets have development defaults for local readability.
Replace them and follow [the signing-key guide](../operations/signing-keys.md) before
exposing the server. Keep `ZA_OAUTH2__SIGNING_PRIVATE_KEY_B64`, token hash secrets, and
authorization-code hash secrets out of source control and logs. Public keys are
not secret. `ZA_OAUTH2__PREVIOUS_PUBLIC_KEYS` retains verification-only material; never put
an old private key in that collection.

## Identity Workflows

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `ZA_IDENTITY_WORKFLOW__REGISTRATION_ENABLED` | `true` | Mount public signup and new email-verification requests. |
| `ZA_IDENTITY_WORKFLOW__WORKFLOW_TOKENS__DERIVATION_KEY_ID` | `default` | Stable identifier persisted with tokens created by the active derivation key. |
| `ZA_IDENTITY_WORKFLOW__WORKFLOW_TOKENS__DERIVATION_SECRET` | development value | HMAC secret used to reproduce the same workflow link on outbox retry. |
| `ZA_IDENTITY_WORKFLOW__WORKFLOW_TOKENS__PREVIOUS_DERIVATION_SECRETS` | `[]` | JSON array of retained `{key_id, secret}` derivation-key entries. |
| `ZA_IDENTITY_WORKFLOW__WORKFLOW_TOKENS__VERIFY_TOKEN_TTL_SECONDS` | `86400` | Email-verification and email-change token lifetime. |
| `ZA_IDENTITY_WORKFLOW__WORKFLOW_TOKENS__INVITE_TOKEN_TTL_SECONDS` | `604800` | Invitation token lifetime. |
| `ZA_IDENTITY_WORKFLOW__WORKFLOW_TOKENS__RESET_TOKEN_TTL_SECONDS` | `3600` | Password-reset token lifetime. |
| `ZA_BOOTSTRAP__OPERATOR_EMAIL` | unset | Email for the first operator on an empty database. |
| `ZA_BOOTSTRAP__OPERATOR_PASSWORD` | unset | Initial operator password. |
| `ZA_BOOTSTRAP__ORGANIZATION_NAME` | `Zero Auth Lite` | Organization name created for the first operator. |
| `ZA_BOOTSTRAP__FIRST_NAME` | `Bootstrap` | First name assigned to the first operator. |
| `ZA_BOOTSTRAP__LAST_NAME` | `Operator` | Last name assigned to the first operator. |

The exact verification, password-reset, and invitation destinations are configured
under `ZA_UI__URLS__...`. In `deployment` mode reachable workflow URLs must use
HTTPS so their single-use tokens are not placed in plaintext links. A strict
Client Credentials machine profile may retain the unused local defaults.

Verification, invitation, and reset lifetimes are configured under
`ZA_IDENTITY_WORKFLOW__WORKFLOW_TOKENS__...`. These single-use artifacts are separate from
OAuth2 access and refresh tokens. Remove bootstrap credentials after the first
operator has been created. Replace the derivation secret in production.

The selected identity transport remains part of the server surface, except for
public registration. Set `ZA_IDENTITY_WORKFLOW__REGISTRATION_ENABLED=false` to remove
`POST /api/v1/auth/register` and `/api/v1/auth/email/verify/request` from
runtime and OpenAPI. Confirmation stays mounted for already-issued tokens.
This closes new self-registration without disabling invitations,
administrative user creation, password recovery, or
`/api/v1/auth/email/change/confirm`. The three workflow URLs select the exact
consumer pages placed in notification links. Built-in mode validates their
canonical Zero Auth Lite paths; external mode accepts application-owned paths
that submit tokens to the confirmation endpoints.

To rotate it safely, choose a new `ZA_IDENTITY_WORKFLOW__WORKFLOW_TOKENS__DERIVATION_KEY_ID`, set the new
`ZA_IDENTITY_WORKFLOW__WORKFLOW_TOKENS__DERIVATION_SECRET`, and move the previous identifier and secret into
`ZA_IDENTITY_WORKFLOW__WORKFLOW_TOKENS__PREVIOUS_DERIVATION_SECRETS`. For example, after replacing the original
`default` key with `2026-09`:

```bash
export ZA_IDENTITY_WORKFLOW__WORKFLOW_TOKENS__DERIVATION_KEY_ID=2026-09
export ZA_IDENTITY_WORKFLOW__WORKFLOW_TOKENS__DERIVATION_SECRET="new-secret-at-least-32-characters"
export ZA_IDENTITY_WORKFLOW__WORKFLOW_TOKENS__PREVIOUS_DERIVATION_SECRETS='[{"key_id":"default","secret":"old-secret-at-least-32-characters"}]'
```

Retain an old key until no stored token references its identifier. A missing or
incorrect retained key makes the corresponding outbox delivery fail and retry;
the dispatcher never sends a reconstructed link whose hash differs from the
stored token.

## Mail Delivery

These settings configure rendering and SMTP delivery after an authentication
notification has been committed to the outbox. The database transaction records
the delivery intention; it never includes template rendering or SMTP network I/O.

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `ZA_MAIL__ENABLED` | `true` | Deliver notification email through the configured SMTP server. |
| `ZA_MAIL__DEFAULT_FROM_EMAIL` | `zero-auth-lite@example.com` | Default envelope and message-header sender address. |
| `ZA_MAIL__DEFAULT_FROM_NAME` | `Zero Auth Lite` | Display name paired with the default sender address. |
| `ZA_MAIL__REPLY_TO_EMAIL` | unset | Default reply-to address when a message does not provide one. |
| `ZA_MAIL__TEMPLATE_DIR` | packaged templates | Filesystem directory used instead of the packaged email template root. |
| `ZA_MAIL__SMTP_HOST` | `localhost` | SMTP server hostname or address. |
| `ZA_MAIL__SMTP_PORT` | `1025` | SMTP server port. |
| `ZA_MAIL__SMTP_USERNAME` | unset | SMTP username; setting it enables SMTP authentication. |
| `ZA_MAIL__SMTP_PASSWORD` | unset | SMTP password used with `ZA_MAIL__SMTP_USERNAME`. |
| `ZA_MAIL__SMTP_STARTTLS` | `false` | Upgrade a plain SMTP connection with STARTTLS before authentication. |
| `ZA_MAIL__SMTP_SSL` | `false` | Open an implicit TLS SMTP connection. |
| `ZA_MAIL__SMTP_TIMEOUT_SECONDS` | `10` | Connection and SMTP operation timeout. |

Choose the TLS mode expected by the SMTP server. With
`ZA_MAIL__SMTP_SSL=true`, Zero Auth Lite uses implicit TLS and does not call
STARTTLS; otherwise `ZA_MAIL__SMTP_STARTTLS=true` upgrades the plain connection.
Both modes verify the SMTP server certificate and hostname against the operating
system trust store. Do not enable SSL and STARTTLS together. SMTP authentication
requires a nonempty username and password together; partial credentials are
rejected at startup, as are credentials configured without either TLS mode.
Deployment mode requires SSL or STARTTLS whenever mail delivery is enabled.
It also rejects the packaged `zero-auth-lite@example.com` sender; configure an
address on a domain authorized to send mail for the deployment. SMTP hostnames
must not be blank. Keep SMTP credentials out of source control and logs. A custom
`ZA_MAIL__TEMPLATE_DIR` replaces the packaged template root and must
contain the same relative template paths used by authentication notifications.

## Notification Outbox

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `ZA_NOTIFICATION_OUTBOX__POLL_INTERVAL_SECONDS` | `1` | Delay between dispatcher polls. |
| `ZA_NOTIFICATION_OUTBOX__BATCH_SIZE` | `20` | Maximum events claimed per poll. |
| `ZA_NOTIFICATION_OUTBOX__LEASE_SECONDS` | `60` | Time before a crashed worker's claim is recoverable. |
| `ZA_NOTIFICATION_OUTBOX__RETRY_MAX_SECONDS` | `300` | Maximum exponential retry delay. |
| `ZA_NOTIFICATION_OUTBOX__RETENTION_SECONDS` | `604800` | Terminal outbox-row retention before cleanup. |
| `ZA_NOTIFICATION_OUTBOX__CLEANUP_INTERVAL_SECONDS` | `3600` | Periodic cleanup interval. |
| `ZA_NOTIFICATION_OUTBOX__CLEANUP_BATCH_SIZE` | `100` | Maximum terminal events deleted per cleanup transaction. |
| `ZA_NOTIFICATION_OUTBOX__SHUTDOWN_TIMEOUT_SECONDS` | `15` | Maximum graceful outbox-worker shutdown wait. |

The dedicated outbox worker runs the dispatcher. HTTP success means that a
notification was transactionally scheduled; SMTP delivery may happen just
after the response.
Delivery is at least once, so mail consumers should tolerate duplicates.
Retained rows expose a terminal processing result for delivered and deliberately
discarded notifications, as well as permanent payload, template, or handler
failures. SMTP transport failures remain pending and use the configured retry
backoff.

`ZA_MAIL__ENABLED=false` disables external email delivery, not the
outbox worker. Every currently supported outbox event is an email notification,
so the dispatcher completes each one with an explicit discarded result and does
not create or invalidate its workflow token. Security-session cleanup is not an
outbox event: session revocation remains part of the originating SQL
transaction.
Development mode permits this setting for focused tests and demonstrations,
but affected users cannot receive or complete a newly requested workflow.
Deployment mode permits disabled mail only when identity-workflow presentation
and the interactive authentication API routes, browser sessions, and Refresh Token are all
disabled. Otherwise startup rejects the configuration.

Deployment validation follows the enabled capabilities. A Client
Credentials-only server that disables browser sessions, Refresh Token, and both
identity-workflow transports does not require a workflow-token derivation secret
or email frontend URL. Authorization Code requires its hash secret; every
token-issuing grant requires the token hash secret and private signing key.
JWKS-only publication does not require grant hash secrets or a private signing
key, but still requires non-development public verification material and a key
identifier.

## Python API

::: app.oauth2.settings.OAuth2Settings
    options:
      members:
        - is_grant_enabled
        - enabled_grants
        - has_enabled_grants
        - protocol_enabled

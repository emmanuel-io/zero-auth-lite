# Settings Reference

Zero Auth Lite loads one immutable Pydantic settings snapshot when `create_app()` is
called. It reads the optional `zero-auth-lite.toml` file from the working directory;
`ZA_CONFIG_FILE` selects another file and requires that file to exist. TOML
tables mirror the settings model, so `session.csrf.header_name` is written as
`header_name` under `[session.csrf]`.

Environment overrides use the `ZA_` prefix and `__` between nested sections.
For example, `session.csrf.header_name` becomes
`ZA_SESSION__CSRF__HEADER_NAME`. Values are resolved in this order: explicit
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
| `ZA_DB_ECHO` | `false` | Emit SQLAlchemy statements for local debugging. |
| `ZA_RUNTIME_DIR` | `/tmp/zero-auth-lite` | Ephemeral process state shared by workers on one host. |
| `ZA_SNOWFLAKE_NODE_ID` | unset | Reserve one exact Snowflake node instead of allocating automatically. |
| `ZA_CORS__ENABLED` | `true` | Install CORS middleware for configured browser origins. |
| `ZA_CORS__ALLOWED_ORIGINS` | local origins | JSON array of exact browser origins accepted by CORS. |
| `ZA_CORS__ALLOW_CREDENTIALS` | `true` | Allow browsers to include credentials on accepted cross-origin requests. |
| `ZA_CORS__ALLOW_METHODS` | `["*"]` | JSON array of HTTP methods accepted by CORS preflight checks. |
| `ZA_CORS__ALLOW_HEADERS` | `["*"]` | JSON array of request headers accepted by CORS preflight checks. |
| `ZA_CORS__EXPOSE_HEADERS` | `["X-CSRF-Token","X-Request-Id"]` | Response headers browser JavaScript may read. |

`ZA_CORS__ALLOWED_ORIGINS` is always an explicit collection, even for one origin. For
example: `ZA_CORS__ALLOWED_ORIGINS='["https://app.example"]'`. A bare
string is rejected so the middleware cannot interpret it using substring
membership.

SQLAlchemy is the canonical persistence baseline. Browser sessions, OAuth2
state, authorization codes, identity, organization, client, and durable lifecycle
state remain in SQL.

`ZA_DB_PATH` is deliberately a SQLite file path rather than an arbitrary
SQLAlchemy URL. Other database engines and remote database URLs are not part of
the canonical server contract.

Each process that generates public IDs reserves one of the 1024 Snowflake node
identifiers. This includes ASGI workers and the outbox worker. Automatic
allocation is safe only when they share the `snowflake/` subdirectory of
`ZA_RUNTIME_DIR` on the same POSIX host. Setting
`ZA_SNOWFLAKE_NODE_ID` makes one process reserve that exact node;
starting another process with the same value fails instead of risking duplicate
IDs.

`ZA_RUNTIME_DIR` contains disposable process coordination state, not
database or application data. A managed Linux service can set it to
`/run/zero-auth-lite` after creating that directory with the service user's
ownership. Keep persistent state in the configured database or data volume
instead.

The local Compose stack pins Caddy to `172.30.0.10` and sets
`ZA_APP__TRUSTED_PROXY_IPS` to `172.30.0.10/32`. Keep this trust list empty when the
server has no reverse proxy. In other topologies, list only proxy addresses you
control; trusting a broad network lets other peers forge the source metadata
recorded with browser sessions through forwarded headers.

`development` keeps the committed local defaults convenient for the direct and
Compose examples. Set `ZA_APP__ENVIRONMENT=deployment` for any deployed
server. That mode fails before startup while a checked-in session, OAuth2,
workflow-token, or signing secret remains in use. It also requires explicit
trusted hosts, secure session cookies when sessions are enabled, non-local
browser and workflow topology, and mail delivery because verification,
invitation, and password-recovery workflows depend on it.
`localhost`, subdomains ending in `.localhost`, and loopback IP addresses are
rejected in issuer, email, cookie-domain, CORS, and CSRF settings. This
validation is a minimum safety boundary, not a complete production-readiness
claim.

## Built-In Web UI

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `ZA_UI__AUTHENTICATION` | `builtin` | Select built-in authentication forms or the `external` JSON transport. Session-backed forms also require browser sessions. |
| `ZA_UI__EXTERNAL_LOGIN_URL` | unset | Absolute external login-page URL used for interactive OAuth2 continuations in external authentication mode. |
| `ZA_UI__OAUTH2_INTERACTION` | `builtin` | Control OAuth2 consent and device-code presentation independently; set `disabled` to remove it. |

`ui.authentication` selects the built-in forms or external JSON transport.
`ui.oauth2_interaction` independently selects OAuth2 consent and Device Code
presentation. Setting it to `disabled` denies requests that need login or
consent; it does not hand those decisions to an API client. Device Code cannot
be enabled in that mode because verification requires the built-in UI.
The canonical [startup route matrix](routes.md#startup-route-matrix) lists the
resulting surfaces and invalid combinations. See the
[built-in authentication UI](../guides/builtin-authentication-ui.md) for the
default server-rendered flow. In external mode, the server adds only opaque
transaction or device continuation identifiers to `ui.external_login_url`; see
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
| `ZA_SESSION__ENABLED` | `true` | Mount browser-session routes and services. |
| `ZA_SESSION__COOKIE_DOMAIN` | `zero-auth-lite.localhost` | Domain attribute shared by the browser-session cookie. Use an empty value for a host-only cookie. |
| `ZA_SESSION__COOKIE_NAME` | `sessionid` | Opaque browser-session cookie name. |
| `ZA_SESSION__COOKIE_SECURE` | `true` | Send the session cookie only over HTTPS. |
| `ZA_SESSION__COOKIE_SAME_SITE` | `lax` | Browser cross-site cookie policy. |
| `ZA_SESSION__TTL_SECONDS` | `28800` | Sliding session lifetime in seconds. |
| `ZA_SESSION__ABSOLUTE_TTL_SECONDS` | `604800` | Seven-day maximum lifetime regardless of activity. |
| `ZA_SESSION__CLEANUP_BATCH_SIZE` | `100` | Maximum expired or revoked sessions deleted by one cleanup operation. |
| `ZA_SESSION__SLIDE_SECONDS` | `1800` | Remaining-lifetime threshold for extending SQL expiry and age threshold for a standalone persisted `last_seen_at` update. |
| `ZA_SESSION__MAX_SESSIONS_PER_USER` | `10` | Concurrent session limit per user. |
| `ZA_SESSION__ID_HASH_SECRET` | development value | Secret used for session lookup hashing. |

`ttl_seconds` cannot exceed `absolute_ttl_seconds`, and `slide_seconds` cannot
exceed `ttl_seconds`. Cookies for an existing session use its effective
remaining SQL lifetime rather than restarting the full configured TTL on every
response. With the defaults, activity inside the sliding window renews the
eight-hour session up to the seven-day absolute limit. `slide_seconds` also
limits standalone `last_seen_at` persistence between expiry extensions.
Expired-session cleanup deletes at most `cleanup_batch_size` rows per request;
repeat it until it reports zero deletions. The explicit `status=all` operation
remains intentionally unbounded.
Replace the development hash secret in every deployment.

## CSRF

CSRF settings are nested under `session.csrf`.

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `ZA_SESSION__CSRF__PATTERN` | `synchronizer_token` | CSRF validation pattern. |
| `ZA_SESSION__CSRF__ORIGIN_CHECK_ENABLED` | `true` | Validate browser request origins. |
| `ZA_SESSION__CSRF__PUBLIC_ORIGIN` | local auth origin | External browser origin. |
| `ZA_SESSION__CSRF__TRUSTED_ORIGINS` | local origins | Additional accepted origins. |
| `ZA_SESSION__CSRF__HEADER_NAME` | `X-CSRF-Token` | Request and exposure header. |
| `ZA_SESSION__CSRF__EXPOSE_TOKEN` | `header` | Expose CSRF state through `header` or a readable `cookie`. |
| `ZA_SESSION__CSRF__COOKIE_DOMAIN` | `zero-auth-lite.localhost` | Domain attribute shared by the CSRF cookie. Use an empty value for a host-only cookie. |
| `ZA_SESSION__CSRF__COOKIE_NAME` | `csrftoken` | CSRF cookie name when used. |
| `ZA_SESSION__CSRF__COOKIE_SECURE` | `true` | Send the CSRF cookie only over HTTPS. |
| `ZA_SESSION__CSRF__COOKIE_SAME_SITE` | `lax` | Browser cross-site policy for the CSRF cookie. |
| `ZA_SESSION__CSRF__TTL_SECONDS` | `28800` | Stateless pre-session CSRF cookie lifetime. Authenticated CSRF cookies follow the browser-session lifetime. |

The cookie domain, public origin, trusted origins, proxy behavior, and OAuth2
issuer must describe the same external topology.
When sessions are enabled, the configured CSRF header is automatically allowed
by CORS. It is also exposed by CORS when CSRF exposure uses the header transport.
In `deployment` mode, startup requires both the session and CSRF cookies to be
`Secure`, rejects local-only cookie domains, and requires CORS and CSRF origins
to be exact, non-local absolute HTTPS origins. Separate frontend and
identity-provider origins remain valid configurations.

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
| `ZA_OAUTH2__JWT_ISSUER` | local HTTPS auth origin | Exact public issuer identifier. |
| `ZA_OAUTH2__JWT_AUDIENCE` | `zero-auth-lite-example-api` | Intended access-token audience. |
| `ZA_OAUTH2__JWT_KEY_ID` | `local-dev-key` | Current signing key identifier. |
| `ZA_OAUTH2__PRV_KEY_B64` | development key | Base64-encoded raw 32-byte Ed25519 private signing key. |
| `ZA_OAUTH2__PUB_KEY_B64` | development key | Base64-encoded raw 32-byte Ed25519 public verification key matching the private key. |
| `ZA_OAUTH2__PREVIOUS_PUBLIC_KEYS` | `[]` | JSON array of retained `{kid, pub_key_b64}` verification keys during rotation. |
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
sessions. Device verification additionally requires the built-in UI because no
external verification URL is supported. Settings validation rejects invalid
combinations before startup.

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
client, authorization, and token-session administration routes require at
least one enabled grant; JWKS publication alone does not mount them.

A machine-to-machine deployment may disable browser sessions only after also
disabling authorization code, device code, and OIDC. The canonical machine
profile also disables Refresh Token because a new `client_credentials`-only
installation has no grant that issues refresh tokens. Keep Refresh Token
temporarily enabled only during a controlled transition that must continue to
accept refresh-token families issued by an earlier interactive configuration.
Revocation, introspection, OAuth2 metadata, JWKS, and client administration
routes remain available. Those administration routes still require a
user-backed operator; use the local
[machine-client provisioning command](../operations/oauth2-client-provisioning.md)
when the deployment has no browser authentication.

The canonical server rejects a configuration that disables browser sessions
without leaving an OAuth2 grant enabled. JWKS publication alone is not an
authentication mechanism. In `deployment` mode, an enabled OAuth2 surface also
requires an HTTPS issuer.

Signing and hashing secrets have development defaults for local readability.
Replace them and follow [the signing-key guide](../operations/signing-keys.md) before
exposing the server. Keep `ZA_OAUTH2__PRV_KEY_B64`, token hash secrets, and
authorization-code hash secrets out of source control and logs. Public keys are
not secret. `ZA_OAUTH2__PREVIOUS_PUBLIC_KEYS` retains verification-only material; never put
an old private key in that collection.

## Identity Workflows

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `ZA_AUTH__REGISTRATION_ENABLED` | `true` | Mount public signup and new email-verification requests. |
| `ZA_AUTH__EMAIL__FRONTEND_BASE_URL` | local auth origin | Base URL hosting the verification, reset, and invitation pages. |
| `ZA_AUTH__TOKENS__DERIVATION_KEY_ID` | `default` | Stable identifier persisted with tokens created by the active derivation key. |
| `ZA_AUTH__TOKENS__DERIVATION_SECRET` | development value | HMAC secret used to reproduce the same workflow link on outbox retry. |
| `ZA_AUTH__TOKENS__PREVIOUS_DERIVATION_SECRETS` | `[]` | JSON array of retained `{key_id, secret}` derivation-key entries. |
| `ZA_AUTH__TOKENS__VERIFY_TOKEN_TTL_SECONDS` | `86400` | Email-verification and email-change token lifetime. |
| `ZA_AUTH__TOKENS__INVITE_TOKEN_TTL_SECONDS` | `604800` | Invitation token lifetime. |
| `ZA_AUTH__TOKENS__RESET_TOKEN_TTL_SECONDS` | `3600` | Password-reset token lifetime. |
| `ZA_BOOTSTRAP__OPERATOR_EMAIL` | unset | Email for the first operator on an empty database. |
| `ZA_BOOTSTRAP__OPERATOR_PASSWORD` | unset | Initial operator password. |
| `ZA_BOOTSTRAP__ORGANIZATION_NAME` | `Zero Auth Lite` | Organization name created for the first operator. |
| `ZA_BOOTSTRAP__FIRST_NAME` | `Bootstrap` | First name assigned to the first operator. |
| `ZA_BOOTSTRAP__LAST_NAME` | `Operator` | Last name assigned to the first operator. |

`ZA_AUTH__EMAIL__FRONTEND_BASE_URL` must be an exact HTTP(S) origin: credentials, paths, query
strings, and fragments are rejected. In `deployment` mode it must also use
HTTPS so verification, password-reset, invitation, and email-change tokens are
not placed in plaintext links.

Verification, invitation, and reset lifetimes are configured under
`ZA_AUTH__TOKENS__...`. These single-use artifacts are separate from
OAuth2 access and refresh tokens. Remove bootstrap credentials after the first
operator has been created. Replace the derivation secret in production.

The selected authentication transport remains part of the server surface,
except for public registration. Set `ZA_AUTH__REGISTRATION_ENABLED=false` to remove
`POST /api/v1/auth/register` and `/api/v1/auth/email/verify/request` from
runtime and OpenAPI. Confirmation stays mounted for already-issued tokens.
This closes new self-registration without disabling invitations,
administrative user creation, password recovery, or
`/api/v1/auth/email/change/confirm`. `ZA_AUTH__EMAIL__FRONTEND_BASE_URL` selects
the origin used in workflow email links. In `builtin` mode it identifies the
Zero Auth Lite origin; in `external` mode it is required to identify the external
consumer that submits tokens to the JSON confirmation endpoints.

To rotate it safely, choose a new `ZA_AUTH__TOKENS__DERIVATION_KEY_ID`, set the new
`ZA_AUTH__TOKENS__DERIVATION_SECRET`, and move the previous identifier and secret into
`ZA_AUTH__TOKENS__PREVIOUS_DERIVATION_SECRETS`. For example, after replacing the original
`default` key with `2026-09`:

```bash
export ZA_AUTH__TOKENS__DERIVATION_KEY_ID=2026-09
export ZA_AUTH__TOKENS__DERIVATION_SECRET="new-secret-at-least-32-characters"
export ZA_AUTH__TOKENS__PREVIOUS_DERIVATION_SECRETS='[{"key_id":"default","secret":"old-secret-at-least-32-characters"}]'
```

Retain an old key until no stored token references its identifier. A missing or
incorrect retained key makes the corresponding outbox delivery fail and retry;
the dispatcher never sends a reconstructed link whose hash differs from the
stored token.

## Transactional Mail

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

Choose the TLS mode expected by the SMTP server. With `ZA_MAIL__SMTP_SSL=true`, Zero Auth Lite
uses implicit TLS and does not call STARTTLS; otherwise `ZA_MAIL__SMTP_STARTTLS=true`
upgrades the plain connection. Keep SMTP credentials out of source control and
logs. A custom `ZA_MAIL__TEMPLATE_DIR` replaces the packaged template root and must
contain the same relative template paths used by authentication notifications.

## Notification Outbox

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `ZA_EVENTS__POLL_INTERVAL_SECONDS` | `1` | Delay between dispatcher polls. |
| `ZA_EVENTS__BATCH_SIZE` | `20` | Maximum events claimed per poll. |
| `ZA_EVENTS__LEASE_SECONDS` | `60` | Time before a crashed worker's claim is recoverable. |
| `ZA_EVENTS__RETRY_MAX_SECONDS` | `300` | Maximum exponential retry delay. |
| `ZA_EVENTS__RETENTION_SECONDS` | `604800` | Delivered-row retention before cleanup. |
| `ZA_EVENTS__CLEANUP_INTERVAL_SECONDS` | `3600` | Periodic cleanup interval. |
| `ZA_EVENTS__CLEANUP_BATCH_SIZE` | `100` | Maximum delivered events deleted per cleanup transaction. |
| `ZA_EVENTS__SHUTDOWN_TIMEOUT_SECONDS` | `15` | Maximum graceful outbox-worker shutdown wait. |

The dedicated outbox worker runs the dispatcher. HTTP success means that a
notification was transactionally scheduled; SMTP delivery may happen just
after the response.
Delivery is at least once, so mail consumers should tolerate duplicates.
Retained rows expose a terminal processing result for delivered and deliberately
discarded notifications.

`ZA_MAIL__ENABLED=false` disables external email delivery, not the
outbox worker. Every currently supported outbox event is an email notification,
so the dispatcher completes each one with an explicit discarded result and does
not create or invalidate its workflow token. Security-session cleanup is not an
outbox event: session revocation remains part of the originating SQL
transaction.
Development mode permits this setting for focused tests and demonstrations,
but affected users cannot receive or complete a newly requested workflow.
Deployment mode therefore rejects disabled mail delivery at startup.

## Python API

::: app.oauth2.settings.OAuth2Settings
    options:
      members:
        - is_grant_enabled
        - enabled_grants
        - has_enabled_grants
        - protocol_enabled

# Route Reference

This page is the canonical inventory of HTTP methods, paths, authentication
requirements, and feature-dependent route availability. Guides link here
instead of repeating route tables that could drift.

The canonical server separates versioned application APIs from standardized
OAuth2/OIDC endpoints. Browser transport, identity workflows, and operator
control-plane APIs are application-owned contracts under `/api/v1`.

## Route Families And Authentication

| Prefix | Contract owner | Typical authentication | CSRF |
| --- | --- | --- | --- |
| `/api/v1/sessions` | Canonical browser transport | Credentials or session cookie | Required for cookie-authenticated state changes |
| `/api/v1/auth` | Canonical identity workflows | Workflow-specific or public | Route-specific |
| `/api/v1/oauth2` | External OAuth2 interaction adapters | Browser session | Required for decisions |
| `/api/v1/me` | Canonical self-service API | Browser session or user Bearer token; password change and deletion require a browser session | Required for cookie-authenticated state changes |
| `/api/v1/organization` | Organization administration | Organization-admin session or user Bearer token | Required for cookie-authenticated state changes |
| `/api/v1/server` | Server control plane | Operator session or user Bearer token; explicitly documented machine operations also accept a client-credentials token | Required for cookie-authenticated state changes |
| `/oauth2`, `/.well-known/*` | OAuth2/OIDC protocols | Endpoint-specific | Required only for cookie-authenticated browser decisions |
| `/`, `/login`, `/consent`, workflow pages | Built-in web presentation | Anonymous or browser session | Hidden form token plus origin validation for state-changing forms |

Server support routes are mounted independently from the optional application
and protocol surfaces:

| Method | Path | Authentication | Success | Purpose |
| --- | --- | --- | --- | --- |
| `GET` | `/health/live` | Public | `200` | Report that the application process can serve requests without consulting SQLite. |
| `GET` | `/health/ready` | Public | `200`, `503` | Report whether SQLite is reachable and migrated to the checkout's Alembic heads. |
| `GET` | `/api/docs` | Public | `200` | Serve Swagger UI. |
| `GET` | `/api/redocs` | Public | `200` | Serve ReDoc. |
| `GET` | `/api/docs/openapi.json` | Public | `200` | Return the generated OpenAPI document. |
| `GET` | `/docs/oauth2-redirect` | Public | `200` | Complete Swagger UI OAuth2 redirects. |

Liveness returns `{"status":"ok"}` without consulting SQLite. Readiness reads
the database's Alembic revision and compares it with every head shipped in the
current checkout. It returns the same success payload when they match, or
`503 {"status":"not_ready"}` without exposing connection or migration details.

Every `/api/v1` operation documents the shared `503 DATABASE_BUSY` response.
SQLite permits one writer at a time; when the configured busy timeout cannot
resolve contention, clients receive `Retry-After: 1` and may retry the complete
request. OAuth2 protocol routes translate the same condition through their
OAuth2 error contract instead of the application error envelope.

With the local Compose HTTPS origin, prefix those paths with
`https://auth.zero-auth-lite.localhost:8443`.

## Startup Route Matrix

This table is the canonical reference for settings-driven route composition.
Other guides link here instead of restating the mounting rules.

| Startup condition | HTML routes | JSON routes | Protocol behavior |
| --- | --- | --- | --- |
| `ui.identity_workflow_mode=builtin`, `api.interactive_auth_routes_enabled=true`, `browser_session.enabled=true` | Built-in identity-workflow pages | `/api/v1/sessions/*` and `/api/v1/auth/*` | Default profile; HTML and JSON adapters coexist. |
| `ui.identity_workflow_mode=external`, `api.interactive_auth_routes_enabled=true`, `browser_session.enabled=true` | No built-in identity-workflow pages | `/api/v1/sessions/*` and `/api/v1/auth/*` | Provides the transport needed by an external frontend. |
| `ui.identity_workflow_mode=disabled`, `api.interactive_auth_routes_enabled=true` | No built-in identity-workflow pages | `/api/v1/auth/*` and, when sessions are enabled, `/api/v1/sessions/*` | Headless JSON clients consume the workflows; all notification destinations must be absolute HTTP(S) URLs. |
| `ui.identity_workflow_mode=disabled`, `api.interactive_auth_routes_enabled=false` | No identity-workflow pages | No `/api/v1/sessions/*` or `/api/v1/auth/*` transport routes | Machine-only topology; browser sessions, refresh tokens, and self-registration must be disabled. |
| `ui.identity_workflow_mode=builtin`, `api.interactive_auth_routes_enabled=false` | Built-in identity-workflow pages are unchanged | No `/api/v1/sessions/*` or `/api/v1/auth/*` transport routes | Built-in forms call the same services directly. |
| `browser_session.enabled=true`, `ui.management_authentication=builtin` | `/login`, `/logout`, `/management`, `/management/account` | Independent of management selection | Anonymous management navigation returns to `/login` with a validated internal `return_url`. |
| `browser_session.enabled=true`, `ui.management_authentication=external` | `/management` and `/management/account`; no management-owned `/logout` | Requires `api.interactive_auth_routes_enabled=true` | Management login and logout use `ui.urls.login` and `ui.urls.logout`. |
| `browser_session.enabled=false`, `identity_workflow.registration_enabled=false` | No login, logout, or registration routes | No `/api/v1/sessions/*`, registration start routes, or `/api/v1/server/sessions` browser-session maintenance route | Self-registration, Authorization Code, OIDC, and Device Code are rejected at startup; machine grants may remain enabled. |
| `oauth2.authorization_code_enabled=true`, `ui.oauth2_interaction=builtin` | `/consent` | — | Validated unauthenticated requests use the configured login destination; consent is collected when required. |
| Interactive grant enabled, `ui.oauth2_interaction=external` | No built-in consent or device page | Matching `/api/v1/oauth2/*-interactions/*` routes | Protocol navigation uses `ui.urls.authorization_interaction` or `ui.urls.device_interaction`; the server retains every decision. |
| `oauth2.authorization_code_enabled=true`, `ui.oauth2_interaction=disabled` | No `/consent` | — | Requests requiring interactive consent are denied. |
| `oauth2.device_code_enabled=true` | Built-in verification page only in `builtin` mode | External Device interaction API only in `external` mode | Startup requires sessions and a `builtin` or `external` interaction mode. |
| No OAuth2 grant enabled, JWKS enabled | — | No OAuth2 client or token-session administration routes | OAuth2 metadata and `/oauth2/jwks.json` remain available without token endpoints. |
| `browser_session.enabled=true`, `ui.organization_admin_enabled=true` | `/management/organization/*` | Organization API unchanged | A current organization-admin browser session is required. |
| `browser_session.enabled=true`, `ui.operator_enabled=true` | `/management/operator/*` | Server API unchanged | A current server-operator browser session is required. |
| `browser_session.enabled=false` or either administration toggle is false | Corresponding management UI absent | Organization and server APIs unchanged | UI toggles never disable API authority. |

`identity_workflow.registration_enabled=false` removes registration and the ability to
request another self-registration verification message. It is required when
browser sessions are disabled. JSON confirmation stays mounted so a token
issued before the setting changed can still be consumed when
`api.interactive_auth_routes_enabled=true`. Built-in HTML confirmation pages
are selected independently by `ui.identity_workflow_mode`.
Organization, server, self-service, health, and enabled OAuth2/OIDC protocol
routes are not selected by the JSON or presentation settings.

## Management Browser Interfaces

The management interfaces are HTML adapters over the same actor-bound services
used by the versioned APIs. They accept browser sessions only; Bearer tokens
continue to call `/api/v1/me`, `/api/v1/organization`, and `/api/v1/server`
directly.

| Prefix | Actor | Capabilities |
| --- | --- | --- |
| `/management` | Any authenticated browser user | Navigate to the management sections available to the current user. |
| `/management/account` | Any authenticated browser user | Read and update self-owned profile fields. |
| `/management/organization` | Current organization administrator | Organization metadata, users, security-session management and, when grants are enabled, retained OAuth2 sessions. |
| `/management/operator` | Server operator | Organizations, global users, server-wide security-session maintenance and, when grants are enabled, OAuth2 clients. |

Self-service HTML routes:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/management` | Show the authenticated management dashboard. |
| `GET`, `POST` | `/management/account` | Read or update the current user's email, first name, and last name. |
| `GET`, `POST` | `/management/{unmatched_path:path}` | Return an HTML-classified `404` for an unmatched management URL. |

The account route is mounted whenever browser sessions are enabled. It does not
require an organization-admin or operator role. Email replacement creates a
pending address and preserves the current address until verification succeeds.

Organization-administrator HTML routes:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/management/organization` | Show the organization-administration dashboard. |
| `GET` | `/management/organization/settings` | Show the organization metadata form. |
| `POST` | `/management/organization` | Update organization metadata. |
| `GET`, `POST` | `/management/organization/users` | Search, create, or invite users. |
| `GET` | `/management/organization/users/new` | Show the user creation or invitation form. |
| `GET`, `POST` | `/management/organization/users/{user_id}` | Show or replace one organization user. |
| `POST` | `/management/organization/users/{user_id}/invitation` | Resend an invitation to an active, unverified user. |
| `GET`, `POST` | `/management/organization/users/{user_id}/delete` | Confirm and delete one organization user. |
| `GET`, `POST` | `/management/organization/users/{user_id}/sessions/browser/delete` | Confirm and delete the user's browser sessions. |
| `GET`, `POST` | `/management/organization/users/{user_id}/sessions/oauth2/delete` | Confirm and delete the user's OAuth2 sessions. |
| `GET`, `POST` | `/management/organization/users/{user_id}/sessions/revoke` | Confirm and revoke all of the user's sessions. |
| `GET`, `POST` | `/management/organization/sessions/browser/delete` | Confirm and delete this organization's browser sessions. |
| `GET`, `POST` | `/management/organization/sessions/oauth2/delete` | Confirm and delete this organization's OAuth2 sessions. |
| `GET`, `POST` | `/management/organization/sessions/revoke` | Confirm and revoke all sessions attributed to this organization. |
| `GET` | `/management/organization/oauth2/sessions` | Search retained OAuth2 sessions when grants are enabled. |
| `POST` | `/management/organization/oauth2/sessions/{session_id}/revoke` | Explicitly revoke one OAuth2 session. |
| `POST` | `/management/organization/oauth2/clients/{client_id}/revoke` | Explicitly revoke all current-organization token families for one client. |

Server-operator HTML routes:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/management/operator` | Show the operator dashboard. |
| `GET`, `POST` | `/management/operator/organizations` | List or create organizations. |
| `GET` | `/management/operator/organizations/new` | Show the organization creation form. |
| `GET`, `POST` | `/management/operator/organizations/{organization_id}` | Show or update an organization. |
| `GET` | `/management/operator/organizations/{organization_id}/sessions` | Show one organization's security-session actions. |
| `GET`, `POST` | `/management/operator/organizations/{organization_id}/sessions/browser/delete` | Confirm and delete one organization's browser sessions. |
| `GET`, `POST` | `/management/operator/organizations/{organization_id}/sessions/oauth2/delete` | Confirm and delete one organization's OAuth2 sessions. |
| `GET`, `POST` | `/management/operator/organizations/{organization_id}/sessions/revoke` | Confirm and revoke one organization's sessions. |
| `GET`, `POST` | `/management/operator/users` | Search users or create an invitation. |
| `GET` | `/management/operator/users/new` | Show the global invitation form. |
| `GET`, `POST` | `/management/operator/users/{user_id}` | Show or replace a global user. |
| `POST` | `/management/operator/users/{user_id}/invitation` | Resend an invitation to an active, unverified user. |
| `GET`, `POST` | `/management/operator/users/{user_id}/delete` | Confirm and delete a global user. |
| `GET`, `POST` | `/management/operator/users/{user_id}/sessions/browser/delete` | Confirm and delete the user's browser sessions. |
| `GET`, `POST` | `/management/operator/users/{user_id}/sessions/oauth2/delete` | Confirm and delete the user's OAuth2 sessions. |
| `GET`, `POST` | `/management/operator/users/{user_id}/sessions/revoke` | Confirm and revoke all of the user's sessions. |
| `GET` | `/management/operator/sessions` | Show server-wide browser and OAuth2 session maintenance. |
| `POST` | `/management/operator/sessions/cleanup` | Clean one batch of expired or revoked browser sessions. |
| `GET`, `POST` | `/management/operator/sessions/browser/delete` | Confirm and delete every browser session. |
| `GET`, `POST` | `/management/operator/sessions/oauth2/delete` | Confirm and delete every OAuth2 session. |
| `GET`, `POST` | `/management/operator/sessions/revoke` | Confirm and revoke every browser and OAuth2 session. |
| `GET`, `POST` | `/management/operator/oauth2/clients` | List or register clients when grants are enabled. |
| `GET` | `/management/operator/oauth2/clients/new` | Show the client registration form. |
| `GET`, `POST` | `/management/operator/oauth2/clients/{client_id}` | Show or replace a client. |
| `POST` | `/management/operator/oauth2/clients/{client_id}/user-organizations` | Replace user organization assignments. |
| `POST` | `/management/operator/oauth2/clients/{client_id}/machine-organizations` | Replace machine organization access. |
| `POST` | `/management/operator/oauth2/clients/{client_id}/rotate-secret` | Confirm rotation and show the new secret once. |
| `GET`, `POST` | `/management/operator/oauth2/clients/{client_id}/delete` | Confirm and delete a client. |

Every page reloads role authority from current identity state. A user who loses
the organization-admin or operator role cannot keep using a page through an old
session. State-changing forms require the session-bound CSRF token and an
accepted Origin. Destructive actions require an explicit confirmation field.

htmx 4 is served from `/static/vendor/` and replaces list fragments without
moving authorization into the browser. Ordinary links and forms remain usable
without JavaScript and successful mutations follow POST/Redirect/GET. Raw
OAuth2 client secrets appear only in the immediate `no-store` creation or
rotation response and cannot be retrieved afterward.

The shared Content Security Policy permits htmx connections only to the current
origin with `connect-src 'self'`. Browser-route failures are HTML responses;
JSON APIs and OAuth2/OIDC protocol routes retain their own error contracts.

## Browser Sessions

When `api.interactive_auth_routes_enabled=true` and sessions are enabled, the following
JSON session routes are mounted.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/sessions/login` | Verify pre-session CSRF proof and JSON credentials, then create a browser session. |
| `POST` | `/api/v1/sessions/logout` | Revoke `current` (default), `others`, or `all` browser sessions using the JSON `scope`. |
| `GET` | `/api/v1/sessions/csrf` | Issue anonymous pre-session CSRF state or expose authenticated session CSRF state. |

Successful session transport responses use `204 No Content` and communicate
through cookies plus any configured CSRF header or cookie.
Login clients must call `GET /api/v1/sessions/csrf` first, preserve the returned cookie,
and echo the exposed value in the configured header with an accepted `Origin`.
The login JSON body contains the user's `email` and `password`.

## JSON Identity Workflow Transport

The following JSON routes are mounted only when
`api.interactive_auth_routes_enabled=true`.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/auth/register` | Create an organization and its initial user when `identity_workflow.registration_enabled` is true. |
| `POST` | `/api/v1/auth/email/verify/request` | Request a self-registration verification email when `identity_workflow.registration_enabled` is true. |
| `POST` | `/api/v1/auth/email/verify/confirm` | Consume an already-issued self-registration verification token. |
| `POST` | `/api/v1/auth/email/change/confirm` | Consume a pending email-change token. |
| `POST` | `/api/v1/auth/password/forgot` | Request a password-reset email. |
| `POST` | `/api/v1/auth/password/reset` | Consume a reset token, set a password, and verify its recipient email. |
| `POST` | `/api/v1/auth/invite/accept` | Accept an invitation and set the first password. |

These are versioned server contracts rather than OAuth2 protocol endpoints.
They are mounted as part of the canonical identity lifecycle. The registration
and `/email/verify/request` routes are absent when
`identity_workflow.registration_enabled` is false. `/email/verify/confirm` remains available
for already-issued tokens.

## External OAuth2 Interaction Transport

These routes are mounted only with `ui.oauth2_interaction=external`,
`api.interactive_auth_routes_enabled=true`, sessions, and the corresponding interactive grant:

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/oauth2/authorization-interactions/{transaction_id}` | CSRF-protect, bind, and continue a live opaque transaction; return consent details or a validated redirect. |
| `POST` | `/api/v1/oauth2/authorization-interactions/{transaction_id}/decision` | Consume an approved or denied Authorization Code decision. |
| `GET` | `/api/v1/oauth2/device-interactions/{user_code}` | Return safe client and scope details for a live Device Code. |
| `POST` | `/api/v1/oauth2/device-interactions/{user_code}/decision` | Consume an approved or denied Device Code decision. |

The GET routes require a session. POST additionally requires session-bound
CSRF and an accepted origin. All responses are `no-store`; invalid, expired,
consumed, and foreign identifiers share `OAUTH2_INTERACTION_INVALID`.

## Built-In Authentication Transport

The [startup route matrix](#startup-route-matrix) is the source of truth for
route mounting. The server mounts the no-JavaScript, form-urlencoded identity
workflow routes when `ui.identity_workflow_mode=builtin`; the shared landing, login,
and logout routes have the combined conditions stated below.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Show the minimal server landing page when built-in identity workflows or built-in management authentication are enabled. |
| `GET`, `POST` | `/login` | Create a browser session when sessions are enabled and either management authentication is built in or an enabled OAuth2 interaction uses the built-in UI. |
| `GET`, `POST` | `/logout` | Revoke the current browser session when sessions and built-in management authentication are enabled. |
| `GET`, `POST` | `/register` | Create an organization and initial user when `identity_workflow.registration_enabled=true`. |
| `GET`, `POST` | `/resend-verification` | Request a verification email when `identity_workflow.registration_enabled=true`. |
| `GET`, `POST` | `/forgot-password` | Request a password-reset email. |
| `GET`, `POST` | `/verify-email` | Display and submit an already-issued email confirmation token, including after registration is disabled. |
| `GET`, `POST` | `/reset-password` | Display and submit password reset. |
| `GET`, `POST` | `/accept-invite` | Display and submit invitation acceptance. |
| `GET` | `/auth-link-unavailable` | Show the generic invalid, expired, or already-used workflow-link result after a safe redirect. |

The GET requests render CSRF-protected forms. The single-use workflow token
authorizes the identity change, while the form token and origin check prevent
cross-site submission. Successful POST requests use `303 See Other` so browser
refreshes repeat a GET rather than replaying a credential or token mutation.
Mounted UI routes are included in OpenAPI. Authentication forms use the
`Built-in Authentication UI` tag; consent and device pages remain grouped with
their corresponding OAuth2 flows. Authentication UI templates use native HTML
forms and do not load HTMX. In contrast, `/management/account`, `/management/organization`, and
`/management/operator` use the shared management shell, which loads HTMX for progressive
enhancement while keeping ordinary links and forms usable without JavaScript.

OAuth2 interaction pages are presentation routes rather than protocol
endpoints:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/consent` | Continue an authenticated authorization request, consuming it immediately when consent is unnecessary or otherwise collecting a decision. |
| `GET`, `POST` | `/oauth2/device/verify` | Display, approve, or deny a device request. |

## Self-Service And Organization Administration

| Method | Path | Purpose |
| --- | --- | --- |
| `GET`, `PATCH`, `DELETE` | `/api/v1/me` | Read, update, or delete the current identity. |
| `POST` | `/api/v1/me/password` | Verify the current password, replace it, and revoke security sessions. |
| `GET` | `/api/v1/me/sessions` | List the current user's browser sessions with `active_only`, `offset`, and `limit`. |
| `DELETE` | `/api/v1/me/sessions/{session_id}` | Revoke one owned browser session. |
| `GET` | `/api/v1/me/oauth2/sessions` | List active OAuth2 sessions owned by the current user. |
| `DELETE` | `/api/v1/me/oauth2/sessions/{session_id}` | Revoke one owned OAuth2 session and its token family. |
| `GET`, `PATCH` | `/api/v1/organization` | Read or patch current organization metadata. |
| `GET` | `/api/v1/organization/oauth2/sessions` | List retained current OAuth2 token families attributed to the current organization. |
| `DELETE` | `/api/v1/organization/oauth2/clients/{client_id}/tokens` | Revoke a client's token families in the current organization. |
| `DELETE` | `/api/v1/organization/oauth2/sessions/{session_id}` | Revoke one OAuth2 session in the current organization. |
| `GET`, `POST` | `/api/v1/organization/users` | List, create, or invite users in the current organization. |
| `GET`, `PUT`, `PATCH`, `DELETE` | `/api/v1/organization/users/{user_id}` | Manage one user in the current organization. |
| `POST` | `/api/v1/organization/users/{user_id}/invitation` | Resend an invitation without changing account state. |

The current-user browser-session list accepts `active_only` (default `true`),
`offset` (default `0`), and `limit` (default `50`, maximum `100`). It returns
`items`, `offset`, `limit`, and `total`, including the matching total before
pagination. Sessions are ordered by most recent activity, then by session ID.

The current-user and organization OAuth2-session list routes accept `offset`
and `limit`. They return `items`, the applied `offset` and `limit`, and `total`,
the number of records matching the filters before pagination. On both routes,
each item uses `id` for its UUIDv4 session identifier and `scopes` for the
array of granted scope strings.
The organization route is not a session history: revoked families are deleted
and never returned. With `active_only=false`, it additionally returns expired
families whose current token-pair row has not yet been removed by cleanup.

The server derives the organization from the authenticated principal. User update
payloads cannot select `organization_id`, grant operator status, or set a plaintext
password.

Password change, self-deletion, and browser-session management are mounted only
when browser sessions are enabled. Password change and self-deletion accept the
session cookie only and require CSRF protection; a Bearer token carrying
`profile:write` can update ordinary profile fields but cannot change credentials
or delete the identity.

Current-user OAuth2 session inspection and revocation are browser-session-only
and are mounted when browser sessions and at least one OAuth2 grant are enabled.
Revoking an OAuth2 session deletes its stored token state; it does not delete the
client registration or the user's identity.

Every `/api/v1/organization` read operation requires `organization:read`, and every state
change requires `organization:write`. These scopes cover only the current-organization
administration surface. The authenticated user must also hold the organization-admin
role; possessing a `organization:*` scope or the operator role alone does not grant
organization-admin authority.

The organization OAuth2 session routes derive the same boundary from that
explicit organization-admin principal. Revocation ends the OAuth2 session and removes its
stored token family, so those tokens can no longer be used or refreshed. These
revocation responses report the affected rows as `revoked_sessions` and
`revoked_token_states`; one token-state row is not necessarily a token pair. These
`/api/v1/organization/oauth2` session routes are mounted only when at least one
OAuth2 grant is enabled. JWKS publication alone does not mount token-session
administration.

## Server Control Plane Administration

OAuth2 client-administration routes in this section are mounted only when at
least one OAuth2 grant is enabled. The remaining server-administration routes
belong to the permanent identity baseline.

| Method | Path | Purpose |
| --- | --- | --- |
| `DELETE` | `/api/v1/server/sessions` | Delete one configured batch of expired or revoked sessions with `scope=inactive`, or all browser sessions with `scope=all`; `all` also ends the caller's browser session. |
| `GET`, `POST` | `/api/v1/server/organizations` | List or create organizations across the server. |
| `GET`, `PATCH` | `/api/v1/server/organizations/{organization_id}` | Read or patch one organization. |
| `DELETE` | `/api/v1/server/organizations/{organization_id}/sessions` | Revoke all browser and OAuth2 sessions attributed to one organization. |
| `GET`, `POST` | `/api/v1/server/users` | List users or invite an active, unverified user to any organization. |
| `GET`, `PUT`, `PATCH`, `DELETE` | `/api/v1/server/users/{user_id}` | Manage one user across organizations. |
| `POST` | `/api/v1/server/users/{user_id}/invitation` | Resend an invitation to a user in any organization. |
| `GET`, `POST` | `/api/v1/server/oauth2/clients` | List or create OAuth2 clients. |
| `GET`, `PUT`, `DELETE` | `/api/v1/server/oauth2/clients/{client_id}` | Read, replace, or delete a client. |
| `GET`, `PUT` | `/api/v1/server/oauth2/clients/{client_id}/user-organizations` | Read or replace allowed user organizations. |
| `GET`, `PUT` | `/api/v1/server/oauth2/clients/{client_id}/machine-organizations` | Read or replace allowed machine organizations. |
| `POST` | `/api/v1/server/oauth2/clients/{client_id}/secrets` | Rotate a confidential client secret. |

Client creation accepts `user_organization_access` and
`user_organization_ids` together, while machine access starts at `none`. The
general client `PUT` replaces registry fields only and preserves both
organization policies. Each dedicated organization endpoint replaces its mode
and assignments atomically. Client names are trimmed and must contain at least
one visible character. User and machine assignment payloads accept at most 100
distinct organization identifiers.

User-backed organization access has these cardinality rules:

| Mode | Required organization identifiers | Effect |
| --- | --- | --- |
| `unrestricted` | None | Users from any organization may authorize the client. |
| `single` | Exactly one | Only users from that organization may authorize the client. |
| `selected` | One or more | Only users from an explicitly assigned organization may authorize the client. |

The server rejects a mode and assignment set that does not satisfy these rules;
it never persists a partially configured `single` or `selected` policy.

Operator privileges are global and distinct from organization-admin privileges.
The operator-authorized routes in the server API use resource-specific
`organizations:*`, `users:*`, `sessions:write`, and `oauth2_clients:*` scopes.

Replacing a client policy revokes all of that client's OAuth2 sessions when
the replacement removes a scope, grant, active status, organization-access mode, or
organization assignment. Capability additions leave existing sessions intact and do
not expand the scopes already recorded in their tokens. Machine-organization
assignments are current policy rather than token claims, so an existing machine token
with `sessions:write` can use a newly assigned organization immediately.

Organization session revocation is the one explicit-organization control-plane operation
that also accepts an OAuth2 client-credentials principal. The client must carry
`sessions:write`; authorization reloads its current machine policy and assignment
after authentication. A `404` deliberately does not reveal whether an organization is
missing or merely outside a machine client's assignments. Revocation marks
browser sessions unusable, ends OAuth2 sessions, and removes their token states.
Sessions belonging to other organizations and organizationless machine sessions are not
affected.

Successful responses from the authenticated `/api/v1/me`, `/api/v1/organization`,
and `/api/v1/server` surfaces carry `Cache-Control: no-store` and
`Pragma: no-cache`. This includes cookie-authenticated reads, whose requests do
not carry an HTTP `Authorization` header that would otherwise constrain shared
caches.

## OAuth2 And OpenID Connect

Protocol paths below include their canonical `/oauth2` prefix.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET`, `POST` | `/oauth2/authorize` | Start an authorization-code request with PKCE. |
| `POST` | `/oauth2/authorize/decision` | Approve or deny a server-side authorization transaction. |
| `POST` | `/oauth2/token` | Exchange a supported grant for tokens. |
| `POST` | `/oauth2/revoke` | Revoke a token. |
| `POST` | `/oauth2/introspect` | Check token activity as an authenticated client. |
| `POST` | `/oauth2/device_authorization` | Issue device and user codes. |
| `GET` | `/oauth2/jwks.json` | Publish current and overlapping public signing keys. |
| `GET`, `POST` | `/oauth2/userinfo` | Return claims for an access-token subject. |

Discovery uses issuer-derived paths. For the default root-style issuer:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/.well-known/oauth-authorization-server` | Publish OAuth2 authorization-server metadata. |
| `GET` | `/.well-known/openid-configuration` | Publish OpenID Connect provider metadata. |

If the issuer contains a path, the discovery paths follow the OAuth2 and OIDC
well-known URI rules described in [OAuth2 discovery](../guides/oauth2-discovery.md).

There is no OAuth2 master switch. The authorization and device routers are
mounted only for their grants, and token/revocation/introspection routes exist
only when at least one grant is enabled. A JWKS-only configuration exposes
metadata plus `/oauth2/jwks.json` without token endpoints or application-owned
OAuth2 administration routes. OIDC discovery and UserInfo are mounted only
when OIDC is enabled.

Use the generated OpenAPI document as the detailed request and response schema
reference. OAuth2 routes intentionally preserve typed query, form, header,
cookie, and security parameters.

`GET /consent` and both device-verification methods are built-in HTML routes,
not OAuth2 protocol endpoints. When mounted, they remain visible in OpenAPI so
the active browser topology can be inspected by tag. `/oauth2/authorize`
remains the protocol entry point. After validation, it redirects to the
configured login destination and then, when required, to `/consent`; the
browser carries only an opaque persisted transaction identifier.

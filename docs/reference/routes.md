# Route Reference

The canonical server separates versioned application APIs from standardized
OAuth2/OIDC endpoints. Browser transport, identity workflows, and operator
control-plane APIs are application-owned contracts under `/api/v1`.

## Route Families And Authentication

| Prefix | Contract owner | Typical authentication | CSRF |
| --- | --- | --- | --- |
| `/api/v1/sessions` | Canonical browser transport | Credentials or session cookie | Required for cookie-authenticated state changes |
| `/api/v1/auth` | Canonical identity workflows | Workflow-specific or public | Route-specific |
| `/api/v1/me` | Canonical self-service API | Browser session or user Bearer token; password change and deletion require a browser session | Required for cookie-authenticated state changes |
| `/api/v1/organization` | Organization administration | Organization-admin session or user Bearer token | Required for cookie-authenticated state changes |
| `/api/v1/admin` | Server control plane | Operator session or user Bearer token | Required for cookie-authenticated state changes |
| `/oauth2`, `/.well-known/*` | OAuth2/OIDC protocols | Endpoint-specific | Required only for cookie-authenticated browser decisions |
| `/`, `/login`, `/consent`, workflow pages | Built-in web presentation | Anonymous or browser session | Hidden form token plus origin validation for state-changing forms |

Swagger UI is served at `/api/docs`, ReDoc at `/api/redocs`, the OpenAPI
document at `/api/docs/openapi.json`, and the health check at `GET /health`.
With the local Compose HTTPS origin, prefix those paths with
`https://auth.zero-auth-lite.localhost:8443`.

## Startup Route Matrix

This table is the canonical reference for settings-driven route composition.
Other guides link here instead of restating the mounting rules.

| Startup condition | HTML routes | JSON routes | Protocol behavior |
| --- | --- | --- | --- |
| `session.enabled=true`, `ui.authentication=builtin` | `/`, `/login`, `/logout`, and HTML identity-workflow pages | No `/api/v1/sessions/*` or `/api/v1/auth/*` transport routes | Browser authentication uses `/login`. |
| `session.enabled=true`, `ui.authentication=external` | No built-in authentication or identity-workflow forms | `/api/v1/sessions/*` and `/api/v1/auth/*` | Interactive OAuth2 redirects to `ui.external_login_url`. |
| `session.enabled=false` | No login or logout routes | No `/api/v1/sessions/*` and no `/api/v1/admin/sessions` browser-session maintenance route | Authorization Code, OIDC, and Device Code are rejected at startup; machine grants may remain enabled. |
| `oauth2.authorization_code_enabled=true`, `ui.oauth2_interaction=builtin` | `/consent` | — | Validated unauthenticated requests use the configured login destination; consent is collected when required. |
| `oauth2.authorization_code_enabled=true`, `ui.oauth2_interaction=disabled` | No `/consent` | — | Requests requiring interactive consent are denied. |
| `oauth2.device_code_enabled=true` | `/oauth2/device/verify` | — | Startup also requires sessions and `ui.oauth2_interaction=builtin`. |
| No OAuth2 grant enabled, JWKS enabled | — | No OAuth2 client, authorization, or token-session administration routes | OAuth2 metadata and `/oauth2/jwks.json` remain available without token endpoints. |

`auth.registration_enabled=false` additionally removes registration and the
ability to request another self-registration verification message. Confirmation
stays mounted so a token issued before the setting changed can still be
consumed.
Organization, operator, self-service, health, and enabled OAuth2/OIDC routes are not
selected by `ui.authentication`.

## Browser Sessions

When `ui.authentication=external`, the following JSON session routes are mounted.
They are absent in `builtin` mode.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/sessions/login` | Verify pre-session CSRF proof and JSON credentials, then create a browser session. |
| `POST` | `/api/v1/sessions/logout` | Revoke `current` (default), `others`, or `all` browser sessions using the JSON `scope`. |
| `GET` | `/api/v1/sessions/csrf` | Issue anonymous pre-session CSRF state or expose authenticated session CSRF state. |

Successful session transport responses use `204 No Content` and communicate
through cookies plus any configured CSRF header or cookie.
Login clients must call `GET /api/v1/sessions/csrf` first, preserve the returned cookie,
and echo the exposed value in the configured header with an accepted `Origin`.

## External Authentication Transport

The following JSON routes are mounted only when `ui.authentication=external`.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/auth/register` | Create an organization and its initial user when `auth.registration_enabled` is true. |
| `POST` | `/api/v1/auth/email/verify/request` | Request a self-registration verification email when `auth.registration_enabled` is true. |
| `POST` | `/api/v1/auth/email/verify/confirm` | Consume an already-issued self-registration verification token. |
| `POST` | `/api/v1/auth/email/change/confirm` | Consume a pending email-change token. |
| `POST` | `/api/v1/auth/password/forgot` | Request a password-reset email. |
| `POST` | `/api/v1/auth/password/reset` | Consume a reset token, set a password, and verify its recipient email. |
| `POST` | `/api/v1/auth/invite/accept` | Accept an invitation and set the first password. |

These are versioned server contracts rather than OAuth2 protocol endpoints.
They are mounted as part of the canonical identity lifecycle. The registration
and `/email/verify/request` routes are absent when
`auth.registration_enabled` is false. `/email/verify/confirm` remains available
for already-issued tokens.

## Built-In Authentication Transport

When `ui.authentication=builtin`, the JSON auth and session routes above are absent.
The server mounts these no-JavaScript, form-urlencoded routes according to the
same startup settings:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Show the minimal server landing page with session, application, and development-documentation links. |
| `GET`, `POST` | `/login` | Create a browser session when `session.enabled=true`. |
| `GET`, `POST` | `/logout` | Revoke the current browser session when `session.enabled=true`. |
| `GET`, `POST` | `/register` | Create an organization and initial user when `auth.registration_enabled=true`. |
| `GET`, `POST` | `/resend-verification` | Request a verification email when `auth.registration_enabled=true`. |
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
their corresponding OAuth2 flows.

OAuth2 interaction pages are presentation routes rather than protocol
endpoints:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/consent` | Continue an authenticated authorization request and collect consent when required. |
| `GET`, `POST` | `/oauth2/device/verify` | Display, approve, or deny a device request. |

## Self-Service And Organization Administration

| Method | Path | Purpose |
| --- | --- | --- |
| `GET`, `PATCH`, `DELETE` | `/api/v1/me` | Read, update, or delete the current identity. |
| `POST` | `/api/v1/me/password` | Verify the current password, replace it, and revoke security sessions. |
| `GET` | `/api/v1/me/sessions` | List the current user's browser sessions. |
| `DELETE` | `/api/v1/me/sessions/{session_id}` | Revoke one owned browser session. |
| `GET` | `/api/v1/me/authorizations` | List active OAuth2 client grants owned by the current user. |
| `DELETE` | `/api/v1/me/authorizations/{authorization_id}` | Revoke one owned OAuth2 grant and its token family. |
| `GET`, `PATCH` | `/api/v1/organization` | Read or patch current organization metadata. |
| `GET` | `/api/v1/organization/oauth2/sessions` | List retained current OAuth2 token families attributed to the current organization. |
| `DELETE` | `/api/v1/organization/oauth2/clients/{client_id}/tokens` | Revoke a client's token families in the current organization. |
| `DELETE` | `/api/v1/organization/oauth2/sessions/{session_id}` | Revoke one OAuth2 session in the current organization. |
| `GET`, `POST` | `/api/v1/organization/users` | List, create, or invite users in the current organization. |
| `GET`, `PUT`, `PATCH`, `DELETE` | `/api/v1/organization/users/{user_id}` | Manage one user in the current organization. |
| `POST` | `/api/v1/organization/users/{user_id}/invitation` | Resend an invitation without changing account state. |

The authorization and organization OAuth2-session list routes accept `offset`
and `limit`. They return `items`, the applied `offset` and `limit`, and `total`,
the number of records matching the filters before pagination.
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

Authorization inspection is browser-session-only and is mounted when browser
sessions and at least one OAuth2 grant are enabled. Revoking an authorization
ends its OAuth2 session and deletes the stored token pair; it does not delete
the client registration or the user's identity.

Every `/api/v1/organization` read operation requires `organization:read`, and every state
change requires `organization:write`. These scopes cover only the current-organization
administration surface. The authenticated user must also hold the organization-admin
role; possessing a `organization:*` scope or the operator role alone does not grant
organization-admin authority.

The organization OAuth2 session routes derive the same boundary from that
explicit organization-admin principal. Revocation ends the OAuth2 session and removes its
stored token family, so those tokens can no longer be used or refreshed. These
`/api/v1/organization/oauth2` session routes are mounted only when at least one
OAuth2 grant is enabled. JWKS publication alone does not mount token-session
administration.

## Server Operator Administration

OAuth2 client-administration routes in this section are mounted only when at
least one OAuth2 grant is enabled. The remaining server-administration routes
belong to the permanent identity baseline.

| Method | Path | Purpose |
| --- | --- | --- |
| `DELETE` | `/api/v1/admin/sessions?status=expired\|all` | Delete one configured batch of expired sessions, or all browser sessions; `all` also ends the caller's browser session. |
| `GET`, `POST` | `/api/v1/admin/organizations` | List or create organizations across the server. |
| `GET`, `PATCH` | `/api/v1/admin/organizations/{organization_id}` | Read or patch one organization. |
| `DELETE` | `/api/v1/admin/organizations/{organization_id}/sessions` | Revoke all browser and OAuth2 sessions attributed to one organization. |
| `GET`, `POST` | `/api/v1/admin/users` | List users or invite an active, unverified user to any organization. |
| `GET`, `PUT`, `PATCH`, `DELETE` | `/api/v1/admin/users/{user_id}` | Manage one user across organizations. |
| `POST` | `/api/v1/admin/users/{user_id}/invitation` | Resend an invitation to a user in any organization. |
| `GET`, `POST` | `/api/v1/admin/oauth2/clients` | List or create OAuth2 clients. |
| `GET`, `PUT`, `DELETE` | `/api/v1/admin/oauth2/clients/{client_id}` | Read, replace, or delete a client. |
| `GET`, `PUT` | `/api/v1/admin/oauth2/clients/{client_id}/user-organizations` | Read or replace allowed user organizations. |
| `GET`, `PUT` | `/api/v1/admin/oauth2/clients/{client_id}/machine-organizations` | Read or replace allowed machine organizations. |
| `POST` | `/api/v1/admin/oauth2/clients/{client_id}/secrets` | Rotate a confidential client secret. |

Client creation starts with machine access set to `none`, and the general
client `PUT` replaces registry fields and user-backed organization mode. Its
`user_organization_access` field is therefore required rather than inherited
from the stored client. Client names are trimmed and must contain at least one
visible character. Neither contract accepts `machine_organization_access`:
machine mode and its assignments form one atomic contract on the dedicated
`/machine-organizations` endpoint. User and machine assignment payloads accept
at most 100 distinct organization identifiers.

Operator privileges are global and distinct from organization-admin privileges.
The server-operator surface continues to use resource-specific `organizations:*`,
`users:*`, and `oauth2_clients:*` scopes.

Replacing a client policy revokes all of that client's OAuth2 sessions when
the replacement removes a scope, grant, active status, organization-access mode, or
organization assignment. Capability additions leave existing sessions intact and do
not expand the scopes already recorded in their tokens.

Organization session revocation is the one explicit-organization control-plane operation
that also accepts an OAuth2 client-credentials principal. The client must carry
`users:write`; authorization reloads its current machine policy and assignment
after authentication. A `404` deliberately does not reveal whether an organization is
missing or merely outside a machine client's assignments. Revocation marks
browser sessions unusable, ends OAuth2 sessions, and removes their token pairs.
Sessions belonging to other organizations and organizationless machine sessions are not
affected.

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

- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/openid-configuration`

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

# Identity And User Lifecycle

Zero Auth Lite owns a small identity lifecycle in addition to OAuth2/OIDC protocol
endpoints. A user belongs to one organization through an explicit membership
and may authenticate through a browser session. Organization administrators manage users inside
their organization; server operators use a separate control plane that may
cross organization boundaries.

This is the part of the server that makes it an educational identity provider
rather than only an OAuth2 token issuer.

## Actors

- A **user** registers, verifies an email address, signs in, updates their
  profile, and recovers access.
- An **organization administrator** creates, invites, updates, deactivates, or
  deletes users in their own organization.
- A **server operator** manages users and organizations across the whole server
  under `/api/v1/server`.
- An **OAuth2 client** requests delegated or machine access. It does not own the
  user's identity record.

Authentication establishes the current user. Authorization then decides
whether that user may change their own profile, administer their organization,
or use the server control plane.

## Administration Terminology

Zero Auth Lite separates resource scope from authorization roles:

- **server** names resources and operations whose scope is the whole canonical
  server. The HTTP surface is `/api/v1/server`;
- **organization** names resources and operations constrained to the current
  organization. The HTTP surface is `/api/v1/organization`;
- **operator** is the server-wide role that authorizes user-backed operations
  on the server surface;
- **admin** is the organization membership role that authorizes operations on
  the organization surface.

The explicit organization session-revocation operation is the only route on
this surface that also accepts a client-credentials principal with its documented
scope and machine-organization policy. The route reference describes that
exception; it does not turn the machine client into a server operator.

The code follows the same distinction. `ServerUsersService` and `ServerUser*`
describe server-scoped operations and representations. Authorization
dependencies separately require the operator role. These names do not imply a
separate user type.

## Lifecycle Overview

```text
registration ──> unverified user ──> verified active user
                       │                       │
invitation ──> password creation               ├──> deactivated ──> reactivated
                                               │
forgot password ──> single-use reset ──────────┘
                                               │
                                               └──> deleted
```

Verification, invitation, and password-reset tokens are single-use workflow
artifacts. They are not browser sessions, OAuth2 authorization codes, access
tokens, refresh tokens, or ID tokens.

## Registration And Verification

`POST /api/v1/auth/register` requires a non-blank organization name and creates
that organization with its initial user. The server normalizes the organization
name and email address, hashes the password, and starts the configured
verification notification flow. The raw password and verification token are
never stored as reusable plaintext credentials.

Organization names are display labels and do not identify organizations.
Different organizations may use the same name; APIs and persistence
relationships use the stable organization public ID instead.

Public registration is enabled by default. A deployment that provisions users
through invitations or administrative APIs can set
`ZA_IDENTITY_WORKFLOW__REGISTRATION_ENABLED=false`. The registration route and the
ability to request another self-registration verification message are then
absent, including from OpenAPI. Confirmation remains available so a token
issued before the setting changed can still be consumed. Controlled onboarding,
password recovery, and email-change confirmation also continue to work.

The verification flow has two steps:

1. `POST /api/v1/auth/email/verify/request` schedules a single-use verification
   notification without revealing account existence unnecessarily.
2. `POST /api/v1/auth/email/verify/confirm` consumes that token and marks the
   corresponding email as verified.

The verification request belongs to self-registration and is mounted only when
`identity_workflow.registration_enabled` is true. Confirmation is always mounted in the
active authentication transport for already-issued tokens. A pending address
change instead uses `POST /api/v1/auth/email/change/confirm`.

With `ui.identity_workflow_mode=builtin`, notification recipients complete the same
service operations through the server-rendered `GET`/`POST /verify-email`,
`/reset-password`, and `/accept-invite` pages. These HTML adapters use
origin-checked anonymous form CSRF and show one generic error for an invalid,
expired, or consumed link. `ui.urls.verification`, `ui.urls.password_reset`, and
`ui.urls.invitation` are the exact HTTP(S) destinations placed in notifications;
credentials, query strings, and fragments are rejected. With
`ui.identity_workflow_mode=external`, the HTML identity-workflow adapters
are absent. The JSON confirmation APIs are controlled independently by
`api.interactive_auth_routes_enabled`. The `disabled` presentation mode also removes
the HTML adapters without implying that an external frontend exists.

Changing an email address reuses normalization, uniqueness, pending-email, and
verification behavior. Verification of an old address must not prove ownership
of a newly requested address.

Every verification, invitation, and password-reset token is bound by foreign
key to the exact email row that received it. Consumption checks that this row
still has the state required by the flow. Replacing or retiring an address
invalidates its unused tokens in the same transaction, so an old link cannot
verify or reset credentials for a later address.

Verification and password-reset requests capture both the account identifier
and email-row identifier before entering the notification outbox. The worker
reloads that exact row before issuing a token. If its lifecycle state changes
while an event is waiting, the event is discarded instead of targeting a new
address or owner.

An email row has one of three explicit states:

- `current` is the address used for login, identity responses, and OIDC claims;
- `pending` is a proposed replacement awaiting confirmation;
- `retired` is immutable history and no longer reserves its normalized value.

SQLite partial unique indexes allow at most one current and one pending row per
user and prevent active rows from sharing a normalized address. Promoting a
pending row retires the previous current row in the same transaction. A retired
address remains auditable but can immediately be reused by any account.

## Invitations

An organization administrator may create a user without supplying a password. The
server then reuses the invitation event and onboarding flow. The invited user
calls `POST /api/v1/auth/invite/accept` with the single-use token and chooses
their first password.

When the administrator supplies an initial password, the server creates an
active, unverified account and sends the normal email-verification notification.
The user can sign in with that password after proving ownership of the address.

Organization administrators can explicitly resend this notification with
`POST /api/v1/organization/users/{user_id}/invitation`; operators use
`POST /api/v1/server/users/{user_id}/invitation`. Resending replaces the previous
active invitation token. An active, verified account returns an empty success
without receiving another invitation. An inactive account returns
`409 Conflict`; resending an invitation never reactivates it. Repeating an
unchanged email in a user `PATCH` does not resend an invitation.

The invitation proves possession of the invitation channel; it does not grant
operator privileges or allow the recipient to choose another organization.
The server records whether invitation acceptance is still pending. Establishing
or changing a password invalidates every unused invitation and password-reset
token for the account. Delayed notification events created before that security
change are discarded by the worker instead of creating a fresh stale link.

## Password Recovery

1. `POST /api/v1/auth/password/forgot` requests a reset notification.
2. `POST /api/v1/auth/password/reset` consumes the single-use token and stores
   a newly hashed password. Because the token was delivered to the user's
   current email address, consuming it also marks that address as verified.

Reset endpoints should not expose whether an email address exists or is active,
so the request endpoint always returns the same empty success response. The
server sends a reset message and creates a token only for an active account. A
reset token is narrowly scoped to password recovery and must never be accepted
as a session or OAuth2 token. Deactivation invalidates every unused reset token
in the same transaction, and token consumption also checks that the account is
still active. Password reset never reactivates a deactivated account; operator
or organization-administrator action is still required.

## Password Policy

Every credential-writing path applies the same password policy: registration,
invitation acceptance, password reset, self-service changes, and administrative
creation or replacement. A password must contain at least eight characters,
including one lowercase letter, one uppercase letter, one digit, and one of
`!@#$%^&*()-_=+[]{};:,.<>?/`. Password inputs are limited to 1,024 characters
before they reach the password hasher.

The server validates this policy before hashing. It stores only the resulting
password hash and never returns the submitted password. Meeting the composition
rules is a minimum input requirement, not evidence that a password is unique or
safe to reuse; clients should still encourage password-manager-generated
credentials.

After a successful login, the password provider checks whether the stored hash
still matches its current algorithm and cost policy. When an upgrade is needed,
the server computes the replacement outside the SQLite transaction and writes it
conditionally with the new browser session. A concurrent password change wins and
prevents that session from being created. Confidential OAuth2 client secrets use
the same conditional upgrade rule during client authentication.

## Self-Service Identity

Authenticated users manage their current identity, password, browser sessions,
and OAuth2 sessions under `/api/v1/me`. The
[route reference](../reference/routes.md#self-service-and-organization-administration)
is the canonical inventory of methods and paths; this guide explains their
lifecycle and authorization behavior.

OAuth2 session lists use offset pagination. Pass `offset` and `limit` and read
results from `items`; `total` reports how many active sessions match before the
page is applied. Organization OAuth2-session administration uses the same
`id` field for the UUIDv4 identifier and the same `scopes` string array. Each
current-user OAuth2 session reports
`last_token_issued_at`, which is the creation or most recent refresh-rotation
time of its token state. Reading an API with an access token does not update
this value.

Both current-user OAuth2 session routes require a browser session. A Bearer
access token cannot inspect or revoke the OAuth2 session that issued it.
Revocation also requires the session-bound CSRF token.

The current identity and organization come from authenticated server state, never
from a user-supplied organization identifier. Successful profile reads and updates
embed the current organization's name in an `organization` object. The self-service response
does not expose user or organization identifiers, nor the server-operator flag;
those fields belong to administrative representations rather than the user's
own profile. The boolean `email_verified` states specifically whether the
current email address has completed its verification workflow.

Reading and updating ordinary profile fields accepts either a browser session
or a user-backed Bearer token with the corresponding profile scope. Changing a
password and deleting the current identity are deliberately narrower: both
require a browser session and CSRF protection, and neither route is mounted
when browser sessions are disabled. The `profile:write` scope therefore never
authorizes credential changes or account deletion.

Profile payloads never accept password fields. Password changes use the
dedicated `/api/v1/me/password` contract so credential verification remains
visible: the caller supplies the current password and a policy-compliant new
password. A successful change revokes every browser session and OAuth2 session,
deletes refresh-token-backed token states, invalidates existing password-reset
tokens and older pending reset requests, and clears the calling browser's
session and CSRF cookies. The user must authenticate again with the new
credential. Self-deletion also clears those browser cookies after the account
and its related authentication state have been removed.

## Organization Administration

`/api/v1/organization/users` lets an organization administrator manage users
only in the organization derived from their authenticated principal.
Its complete method and path inventory lives in the
[route reference](../reference/routes.md#self-service-and-organization-administration).

`PATCH` rejects `organization_id`, `is_operator`, `password`, and explicit `null`
values. `PUT` replaces administrator-managed profile and state fields, not
credentials, identifiers, sessions, or internal persistence state.
User representations expose this state as `email_verified`. Collection filters
and sort keys use the same name.
The `role` field is either `member` or `admin` and belongs to the user's
organization membership. `admin` grants authority only in that organization;
it does not imply the separate server-wide `is_operator` role stored on the
user.

An organization must not lose its last access-capable organization administrator through an
administrative mutation. Such an administrator must be both active and
email-verified. Before removing that access, the service performs a no-op update
on the target user to acquire SQLite's writer lock, then recounts active,
verified administrators in the same transaction. Competing removals therefore
serialize; if the busy timeout is exhausted, the request returns the database
busy contract rather than committing an unsafe mutation. Inactive or
unverified administrators do not satisfy this invariant. A mutation that
would break the invariant returns `409 LAST_ACTIVE_ORGANIZATION_ADMIN`; it is
a conflict with organization state, not a missing permission.

## Operator Administration

The `/api/v1/server/users` and `/api/v1/server/organizations` routes are an explicit
server control plane. Operator authorization is global and therefore must not
be inferred from the organization-admin role. Keeping the paths separate makes the
change in trust boundary visible in both code and OpenAPI.

`POST /api/v1/server/users` always creates an active, unverified invitation. It
does not accept a password or initial lifecycle flags. The server stores an
unusable generated credential, and accepting the invitation sets the first
password and verifies the recipient's email. Granting operator authority, or
mutating a user who already has it, requires server-operator authority and the
`users:write` permission. The actor's organization role is independent and does
not participate in this global authorization decision. Granted authority
cannot be used before the recipient accepts the invitation.

Organization-scoped user contracts neither expose nor accept `is_operator`.
They also reject mutations of accounts that hold that global role. Operator
accounts are changed only through the `/api/v1/server/users` server API, where
operator authority and `users:write` are enforced.

Operators resend an invitation through the dedicated
`POST /api/v1/server/users/{user_id}/invitation` command. This command uses the
same active-account rule as organization administration and does not modify lifecycle
state itself.

Only the operator user contracts can write `email_verified`; organization
administration and self-service treat it as lifecycle-owned state.

The server must retain at least one active, verified operator. Patching,
replacing, deactivating, unverifying, demoting, or deleting the final usable
operator returns `409 Conflict`. The same SQLite writer-lock step occurs before
the operator recount, so concurrent removals cannot both pass the invariant.

## Deactivation, Reactivation, And Deletion

Deactivation prevents new authentication, revokes browser sessions, ends
OAuth2 sessions, removes refresh-token-backed token states, and permanently
invalidates every outstanding identity-workflow link. Verification, email-change,
invitation, and password-reset links issued before deactivation cannot mutate the
inactive account and do not become valid again after reactivation. The canonical API
checks persisted account state and rejects an otherwise unexpired JWT. An external
resource server doing offline JWT validation cannot observe those changes and may
accept that token until expiry.

Changing a user's organization-admin role, operator role, or organization also revokes
browser sessions and ends OAuth2 sessions. Authorization state is read from SQL
on every canonical API request, but revocation additionally prevents an
already-compromised session from inheriting newly granted authority.

Reactivation allows future authentication but does not verify email, reset
credentials, recreate sessions, or restore invalidated workflow links. Deletion is
permanent and removes related
authentication state through explicit `ON DELETE CASCADE` foreign keys. This
includes browser sessions, OAuth2 sessions and tokens, workflow tokens, and the
user's current, pending, and retired email rows. Callers should not treat
deletion as a reversible
suspension. Deactivation and credential changes instead use explicit revocation
because the user row continues to exist.

## Trust Assumptions And Common Mistakes

- Email normalization and uniqueness rules are consistent across every flow.
- Organization and operator authority comes from current server-side state.
- Notification intentions commit with identity mutations and are delivered from
  the SQL outbox. Only token hashes are stored; at-least-once delivery may send
  the same link more than once after a crash.
- Public identifiers are distinct from internal database identifiers.
- Deactivating a user is not the same as deleting them.
- Verifying an email is not the same as authenticating a browser session.
- An OAuth2 scope does not grant organization-admin or operator status by itself.
- Access-token expiry still matters after session or account revocation.

Zero Auth Lite intentionally has no membership resource, generic role engine,
federation, SCIM, or enterprise identity-governance workflow.

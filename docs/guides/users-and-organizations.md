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
  under `/api/v1/admin`.
- An **OAuth2 client** requests delegated or machine access. It does not own the
  user's identity record.

Authentication establishes the current user. Authorization then decides
whether that user may change their own profile, administer their organization,
or use the operator control plane.

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
`ZA_AUTH__REGISTRATION_ENABLED=false`. The registration route and the
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
`auth.registration_enabled` is true. Confirmation is always mounted in the
active authentication transport for already-issued tokens. A pending address
change instead uses `POST /api/v1/auth/email/change/confirm`.

With `ui.authentication=builtin`, notification recipients complete the same
service operations through the server-rendered `GET`/`POST /verify-email`,
`/reset-password`, and `/accept-invite` pages. These HTML adapters use
origin-checked anonymous form CSRF and show one generic error for an invalid,
expired, or consumed link. `auth.email.frontend_base_url` remains the exact
HTTP(S) origin used to construct notification links; credentials, paths, query
strings, and fragments are rejected. It may point at this server or another
consumer. With `ui.authentication=external`, the HTML authentication adapters
are absent and the JSON confirmation APIs are available instead.

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
`POST /api/v1/admin/users/{user_id}/invitation`. Resending replaces the previous
active invitation token. An active, verified account returns an empty success
without receiving another invitation. An inactive account returns
`409 Conflict`; resending an invitation never reactivates it. Repeating an
unchanged email in a user `PATCH` does not resend an invitation.

The invitation proves possession of the invitation channel; it does not grant
operator privileges or allow the recipient to choose another organization.

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

## Self-Service Identity

Authenticated users manage their current identity under `/api/v1/me`:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/me` | Read the current profile. |
| `PATCH` | `/api/v1/me` | Update selected supported profile fields. |
| `POST` | `/api/v1/me/password` | Verify the current password and set a new one. |
| `DELETE` | `/api/v1/me` | Delete the current identity and related auth state. |
| `GET` | `/api/v1/me/sessions` | List owned browser sessions. |
| `DELETE` | `/api/v1/me/sessions/{session_id}` | Revoke one owned session. |
| `GET` | `/api/v1/me/authorizations` | List active OAuth2 client grants. |
| `DELETE` | `/api/v1/me/authorizations/{authorization_id}` | Revoke one owned client grant and token family. |

Authorization lists use offset pagination. Pass `offset` and `limit` and read
results from `items`; `total` reports how many active grants match before the
page is applied. Organization OAuth2-session administration uses the same
response shape. Each current-user authorization reports
`last_token_issued_at`, which is the creation or most recent refresh-rotation
time of its token pair. Reading an API with an access token does not update
this value.

The current identity and organization come from authenticated server state, never
from a user-supplied organization identifier. Successful profile reads and updates
embed the current organization's name in a `organization` object. The self-service response
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
deletes refresh-token-backed token pairs, invalidates existing password-reset
tokens and older pending reset requests, and clears the calling browser's
session and CSRF cookies. The user must authenticate again with the new
credential. Self-deletion also clears those browser cookies after the account
and its related authentication state have been removed.

The authorization routes require a browser session. They let a user inspect
which OAuth2 clients still hold an active stored grant and revoke one without
affecting unrelated browser sessions, clients, or identities.

## Organization Administration

`/api/v1/organization/users` lets an organization administrator manage users
only in the organization derived from their authenticated principal.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/organization/users` | List users in the authenticated organization. |
| `POST` | `/api/v1/organization/users` | Create or invite an organization user. |
| `GET` | `/api/v1/organization/users/{user_id}` | Read one organization user. |
| `POST` | `/api/v1/organization/users/{user_id}/invitation` | Resend an invitation to an active, unverified user. |
| `PATCH` | `/api/v1/organization/users/{user_id}` | Change supported user fields or state. |
| `PUT` | `/api/v1/organization/users/{user_id}` | Replace administrator-managed fields. |
| `DELETE` | `/api/v1/organization/users/{user_id}` | Permanently delete an organization user. |

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

The `/api/v1/admin/users` and `/api/v1/admin/organizations` routes are an explicit
server control plane. Operator authorization is global and therefore must not
be inferred from the organization-admin role. Keeping the paths separate makes the
change in trust boundary visible in both code and OpenAPI.

`POST /api/v1/admin/users` always creates an active, unverified invitation. It
does not accept a password or initial lifecycle flags. The server stores an
unusable generated credential, and accepting the invitation sets the first
password and verifies the recipient's email. Granting operator authority, or
mutating a user who already has it, requires server-operator authority and the
`users:write` permission. The actor's organization role is independent and does
not participate in this global authorization decision. Granted authority
cannot be used before the recipient accepts the invitation.

Organization-scoped user contracts neither expose nor accept `is_operator`.
They also reject mutations of accounts that hold that global role. Operator
accounts are changed only through `/api/v1/admin/users`, where server-operator
authority and `users:write` are enforced.

Operators resend an invitation through the dedicated
`POST /api/v1/admin/users/{user_id}/invitation` command. This command uses the
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
OAuth2 sessions, and removes refresh-token-backed token pairs. The canonical
API checks this persisted state and rejects an otherwise unexpired JWT. An
external resource server doing offline JWT validation cannot observe those
changes and may accept that token until expiry.

Changing a user's organization-admin role, operator role, or organization also revokes
browser sessions and ends OAuth2 sessions. Authorization state is read from SQL
on every canonical API request, but revocation additionally prevents an
already-compromised session from inheriting newly granted authority.

Reactivation allows future authentication but does not verify email, reset
credentials, or recreate sessions. Deletion is permanent and removes related
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

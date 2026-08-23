# Authentication And Authorization

Authentication and authorization answer different questions. Keeping them
separate prevents a valid identity from being mistaken for unlimited access.

## Authentication: Who Are You?

Authentication establishes a principal. A browser session authenticates a
user through an opaque cookie backed by server-side state. A bearer access
token authenticates the user or client represented by that token. OAuth2
client authentication establishes the client, not a browser user.

Both transports resolve to explicit canonical principal contexts. Browser
sessions, OAuth2 users, and OAuth2 clients each keep their own immutable
context type behind small shared protocols. Session and OAuth2 code produce the
authentication facts; authorization dependencies then evaluate those facts
without mixing client-only and user-only fields. The shared contexts and
transport-composing dependencies live in `app/security/`; each authentication
feature remains responsible for resolving its own session or token state.

Passwords, session cookies, authorization codes, access tokens, refresh
tokens, ID tokens, and single-use email tokens are different artifacts. They
must not be accepted interchangeably.

## Authorization: What May You Do?

Authorization happens after authentication. It evaluates the authenticated
principal against the requested action and resource.

- A **role** groups responsibilities such as administrator or operator.
- A **permission** names an application action such as `users:read`.
- An OAuth2 **scope** limits what a client may do with a token.
- **Ownership** asks whether the principal controls a specific resource.
- An **organization boundary** limits which organization's resources are visible.

An organization administrator operates inside one organization. An operator is
a global control-plane role and may act across organizations through the
dedicated `/api/v1/admin/*` surface.

A scope is not automatically an application permission. A resource server must
map token scopes and principal context to an explicit access decision. In the
canonical Zero Auth Lite API, that mapping is intentionally direct and readable:
API permission names such as `users:read` are also exposed as OAuth2 scope
names. A bearer principal receives the intersection of its role-derived
permissions and granted scopes. Browser-session principals are authorized from
their current server-side roles and are not restricted by OAuth2 scopes.
The `profile:write` scope covers ordinary profile fields only. Changing a
password or deleting the current identity requires a browser session and its
CSRF proof, so a Bearer token cannot exercise those sensitive operations.
Current-organization administration intentionally uses the coarse
`organization:read` and `organization:write` scopes across organization
metadata, users, and OAuth2 sessions. Those scopes constrain an
organization-admin token; they do not confer the organization-admin role. The
server-operator API keeps the resource-specific `organizations:*`, `users:*`,
and `oauth2_clients:*` scopes for global control-plane actions.

## Where Decisions Live

Zero Auth Lite provides authenticated user and principal contexts. The application
owns resource-specific authorization policy because only the application knows
the meaning of its resources, roles, and organization relationships.

FastAPI dependencies enforce the complete HTTP authorization contract: roles,
application permissions, OAuth2 scopes, and CSRF proof where applicable.
Actor-bound services repeat the required role check and enforce target-specific
rules such as organization membership, ownership, and lifecycle invariants.
They intentionally do not reinterpret transport permissions or bearer scopes;
those decisions belong to the route boundary. This split keeps direct service
calls safe without maintaining two subtly different permission policies.

## Common Mistakes

- Treating possession of an authorization code as user authentication.
- Treating an ID token as an API access token.
- Assuming a valid signature proves a token is still active.
- Using an internal database ID as an unreviewed public identifier.
- Checking a role but ignoring organization or resource ownership.
- Calling OAuth2 an authentication protocol without explaining the OIDC layer.

Continue with [sessions and CSRF](sessions-and-csrf.md),
[OAuth2 flows](oauth2-flows.md), or [OpenID Connect](openid-connect.md).

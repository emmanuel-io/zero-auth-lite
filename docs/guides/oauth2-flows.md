# OAuth2 Flows

OAuth2 lets a client obtain limited access without receiving the user's
password. Zero Auth Lite keeps each grant in a separate service so authentication,
authorization, and token issuance remain visible.

The transport contract for `/oauth2/*` routes is documented separately in the
[OAuth2 routing guide](../development/oauth2-routing.md). Typed FastAPI query,
form, security, and cookie dependencies are part of that protocol surface.

## Authorization Code With PKCE

**Actors:** user, browser, OAuth2 client, authorization server, and resource
server.

1. The client creates a PKCE verifier and S256 challenge, then sends a typed
   query GET or form POST to `/oauth2/authorize`.
2. The server validates the client, exact redirect URI, PKCE, and requested
   scopes before beginning browser interaction.
3. If needed, the server sends the browser to `/login` or the configured
   external login page, then resumes the opaque server-side transaction at
   `/consent`.
4. Existing authorization policy decides whether consent is needed; the page
   collects only Allow or Deny.
5. The server redirects to the client with a short-lived, single-use code.
6. The client sends the code and verifier to `/oauth2/token`.
7. The server consumes the code, verifies PKCE and client policy, and issues an
   access token plus an optional refresh token and ID token.

Authentication happens before code issuance. Authorization happens when the
user and server approve the client and scopes. The client receives tokens but
never receives the user's password.

PKCE limits the value of a stolen code. It does not replace client
registration, exact redirect URI validation, browser-session authentication,
state, or consent.

Only S256 is supported. The verifier is 43 to 128 unreserved characters and
the challenge is exactly 43 base64url characters. Login and consent use one
expiring server-side transaction. It begins unbound, is atomically bound to the
authenticated user, and is consumed once. The browser submits only
`transaction_id`, `decision`, and CSRF proof to
`/oauth2/authorize/decision`; it cannot edit the original client, callback,
scope, nonce, state, or challenge. This decision POST requires the browser
session and configured CSRF header or hidden-form protection.

## Refresh Tokens And Revocation

**Actors:** OAuth2 client and authorization server; the original user may not
be present.

The client sends a refresh token to `/oauth2/token`. Zero Auth Lite verifies the token
family, client, OAuth2 session, expiry, and current user state before rotating
the refresh token and issuing a new access token. Reuse of an older rotated
refresh token ends the family because it can indicate theft.

Rotation uses an atomic compare-and-swap. If two requests both observe the
current refresh token, only one receives new tokens; the losing in-flight
request receives `invalid_grant` without revoking the winner's token family.
A request that begins after rotation sees the token only in consumed-token
history and still ends the family as reuse. Clients should serialize refreshes
when practical and share the newest token across browser tabs.

No new user authentication normally happens during refresh. A refresh token
represents previously granted authorization. Revocation intentionally ends a
token before expiry; browser cookie deletion does not do that.

Refresh scope narrowing is deliberately not supported: supplying `scope` is
rejected deterministically with `invalid_grant`. Revocation returns bodyless
`200` for valid, unknown, expired, and already-revoked tokens so token
existence is not leaked. Introspection requires a confidential client and
returns only `active: false` for unknown, inaccessible, expired, or revoked
tokens.

## Client Credentials

**Actors:** confidential client, authorization server, and resource server.

1. The client authenticates with its registered credentials at `/oauth2/token`.
2. The server verifies that the client may use `client_credentials` and the
   requested scopes.
3. The server issues an access token whose subject is the client.

There is no browser user, consent screen, ID token, refresh token, or user
impersonation in this grant. The resulting machine principal carries OAuth2
scopes and its configured organization-access policy, but no user roles or implicit
user permissions. Application routes must therefore authorize machine access
explicitly instead of inheriting the baseline organization-user permission set.

Client credentials and the other non-browser protocol endpoints can run with
the browser-session feature disabled. OAuth2 still uses its own session table
to track token families; that state is not a browser login session and does not
set cookies.

## Device Code

**Actors:** constrained device, user, separate browser, OAuth2 client, and
authorization server.

1. The device requests a device code and human-readable user code.
2. The user opens the verification URI in another authenticated browser.
3. The user enters and approves the code.
4. The device polls `/oauth2/token` at the required interval.
5. After approval, the server consumes the device authorization and issues
   tokens.

The user code is not an access token. The server enforces the protocol polling
interval, both codes expire, and approval or denial requires an authenticated
browser user plus CSRF protection. See
[OAuth2 device flow](oauth2-device-flow.md).

Because the current verification endpoint uses browser authentication,
enabling device code requires the session feature. Sessionless interactive
authentication is intentionally not implemented.

## Supported Subset

Zero Auth Lite supports authorization code with mandatory PKCE S256, refresh token,
client credentials, and device code. It also implements revocation and
introspection. It deliberately does not implement password, implicit, hybrid,
dynamic client registration, PAR, JAR, DPoP, or token exchange.

## Introspection And Principal Resolution

Introspection is for an authenticated client or resource server checking token
state. Principal resolution verifies the signed token and then checks stored
token, OAuth2 session, client, identity, organization, and expiry state. Signature
validity alone does not prove that a token remains active.

The OAuth2 session owns the immutable authorization metadata: client, original
grant, granted scope, and optional user and organization. The SQL token pair
contains only the current access and refresh material and is the expiry
authority for its family. The refresh
deadline is fixed when the family is issued, and every rotation preserves that
absolute deadline instead of restarting the configured lifetime. The
associated OAuth2 session records explicit termination through `ended_at`; it
does not duplicate access-token or refresh-token expiry. Introspection,
principal resolution, refresh, and revocation therefore load the session and
current pair together as one token family.

## Client Policy Changes

An operator may replace a client's scopes, grants, active status, and organization
access policy. A change that removes an existing capability atomically ends
every OAuth2 session issued to that client and deletes its current token pairs.
This includes removing a scope or grant, disabling the client, making a
user-organization access mode more restrictive, or removing an assigned user or
machine organization. Previously issued access and refresh tokens therefore stop
working as soon as the administration transaction commits.

Confidential-secret verification deliberately runs outside the SQLite
transaction because password hashing is expensive. Immediately before issuing
or rotating tokens, the server acquires the writer lock and reloads the client.
The fresh row is the authority for its secret, active state, grants, scopes,
and organization policy, so a concurrent reduction cannot issue a token from
stale client state.

Adding a scope, grant, or organization does not revoke existing sessions. Existing
tokens do not gain that new authority: a new authorization or token issuance is
still required. Redirect URI, display-name, and consent-policy changes do not
alter already issued token authority and do not trigger revocation.

## Code Map

Flow code is grouped by protocol concept:

- `app/oauth2/authorization/`: authorization requests, consent transactions,
  PKCE, and code exchange;
- `app/oauth2/tokens/refresh.py`: rotation, revocation, and reuse response;
- `app/oauth2/clients/client_credentials.py`: machine access tokens;
- `app/oauth2/devices/`: device codes, browser approval, and polling;
- `app/oauth2/tokens/introspection.py`: active-token checks;
- `app/oauth2/principal.py`: bearer principal resolution shared by OAuth2-protected application routes and OIDC UserInfo.

See [OpenID Connect](openid-connect.md) for the identity layer added by the `openid`
scope.

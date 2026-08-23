# Browser Sessions And CSRF

Browser sessions answer which user is operating the current browser. Zero Auth Lite
stores session state on the server and gives the browser an opaque `HttpOnly`
cookie. JavaScript does not need to read the session cookie.

In external-authentication mode, the canonical server exposes its versioned
browser-session contract under `/api/v1/sessions`:

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/sessions/login` | Verify pre-session CSRF proof and credentials, then create a browser session. |
| `POST` | `/api/v1/sessions/logout` | Revoke the current, other, or all sessions according to the JSON `scope`. |
| `GET` | `/api/v1/sessions/csrf` | Issue pre-session CSRF state or expose current session CSRF state. |

## Actors And Artifacts

- The **browser** stores the session cookie and submits credentials or CSRF
  tokens.
- The **canonical server** authenticates the user, applies CSRF policy, and
  manages session state.
- The **SQLAlchemy database** keeps expiry, revocation, user, and CSRF
  state.
- The **session cookie** is an opaque identifier, not a bearer access token or
  an identity profile.

## Login

The built-in `GET` and `POST /login` pages perform the same workflow with an
ordinary HTML form. The GET response embeds anonymous CSRF state; the POST
validates the hidden value and origin, delegates credential checking to the
same service, and writes the same cookies. It accepts only opaque OAuth2 or
device continuation identifiers plus a validated same-origin return path; it
never accepts an external caller-provided redirect destination.

The [startup route matrix](../reference/routes.md#startup-route-matrix) is the
canonical reference for choosing the built-in forms or external JSON routes.

1. The browser calls `GET /api/v1/sessions/csrf`. The server creates a random,
   stateless pre-session token and exposes it through the configured transport.
2. The browser retains the CSRF cookie and submits the same value in the
   configured header, with `Origin` (or `Referer` as a fallback) and the JSON
   credentials, to `POST /api/v1/sessions/login`.
3. The server validates the origin and double-submit proof before checking the
   credentials.
4. The authentication service loads the normalized current identity and the
   password hasher verifies the stored password hash outside the SQLite
   transaction.
5. A conditional write rechecks the exact password hash and login eligibility
   while acquiring SQLite's writer lock. A password or lifecycle change that
   committed during verification therefore prevents session creation.
6. The authentication service creates server-side session state and rotates
   the pre-session token into a session-bound CSRF token.
7. The route writes the session cookie and exposes session CSRF state according
   to the configured pattern.
8. The route returns `204 No Content`; profile data remains available from
   `/api/v1/me`.

Authentication happens when the password is verified. Creating the session
preserves that result for later browser requests. The browser never receives
the password hash or the stored session record.

Public browser pages resolve sessions tolerantly: an expired, revoked, or
identity-invalidated cookie is deleted and the request continues as anonymous.
This includes the login and logout entry pages. Protected routes use the strict
resolver, so the same invalid credential still produces `401 Unauthorized`.
CSRF failures and internal errors are never downgraded to an anonymous request.

The server validates expiry and revocation first, then the current user
lifecycle state, and finally CSRF when required. Only a session that passes all
of those checks may slide. Invalid users and sessions therefore cannot update
`last_seen_at` or extend their expiry. The server does not write activity
metadata on every ordinary read: `last_seen_at` is
refreshed after its configured `slide_seconds` age threshold, or alongside a
genuine SQL expiry extension when the session enters the sliding window. A
session already capped by its absolute expiry does not trigger repeated no-op
writes. By default, the sliding lifetime is eight hours, the activity threshold
is thirty minutes, and the absolute lifetime is seven days. This keeps recent
activity useful without turning every authenticated
`GET` into a database write. When login enforces the concurrent-session limit,
it always preserves the newly issued session and removes older sessions using
creation time plus their stable public identifier as a deterministic order.

The session cookie and CSRF cookie have different purposes. The HttpOnly
session cookie identifies an authenticated browser session. The readable CSRF
cookie carries only the pre-session or session-bound proof that must be echoed
in the configured header; it does not authenticate the browser by itself.

FastAPI generates the JSON body, standard `Origin` and `Referer` headers,
session-cookie security scheme, and OAuth2 permission scopes in OpenAPI. A
focused schema adjustment supplies the configured CSRF cookie and header names,
because those names are selected from settings at application startup. Missing
CSRF inputs remain application-level `403` errors rather than FastAPI `422`
transport errors.

The JSON transport is composed in `app/api/v1/browser_sessions/router.py`.
Authentication, CSRF, lifecycle, cookie transport, and revocation remain
separate modules under `app/browser_sessions/` so each route depends only on
the behavior it needs.

## CSRF

Browsers attach cookies automatically. Another site could therefore cause a
browser to send an authenticated request unless the server verifies the origin
and requires a value the other site cannot supply.

Zero Auth Lite supports origin checks and synchronizer-token or double-submit
validation. Cookie flags still matter:

- `HttpOnly` prevents JavaScript from reading the session cookie.
- `Secure` restricts the cookie to HTTPS.
- `SameSite` controls cross-site attachment but does not replace a deliberate
  CSRF policy.
- `Domain` and `Path` determine where the browser sends the cookie.

Cookie-authenticated state changes require the configured CSRF proof. Bearer
tokens have a different threat model because browsers do not attach an
`Authorization` header automatically.

Server-rendered forms carry the proof in a hidden `csrf_token` field. Session
helpers validate it against the stored synchronizer token or double-submit
cookie using the configured pattern. Header-based API clients remain
supported; this is one CSRF policy with two browser transports, not a separate
OAuth2 mechanism.

Login always uses the pre-session cookie and header as a double-submit proof,
including when authenticated requests use the synchronizer-token pattern. This
pre-session token is not stored in SQL. Its configured TTL applies only
before authentication. A successful login replaces it; an authenticated CSRF
cookie follows the effective browser-session lifetime and slides with that
session. Existing session and CSRF cookies are never renewed beyond the earlier
of the sliding SQL expiration and the absolute SQL expiration.

On protected routes, an absent or invalid browser session is an authentication
failure and returns `401`. Session validity is evaluated before synchronizer
token comparison, so expired or revoked authority does not change into a CSRF
error merely because the submitted proof is also wrong. The public
`GET /api/v1/sessions/csrf` initializer is the exception: it resolves the same
current user lifecycle state and replaces stale session transport with
pre-session CSRF state.
Once a valid session cookie is present, a missing or invalid CSRF proof on a
protected state change is a request-authorization failure and returns `403`.

## Logout And Revocation

Logout revokes server-side state and clears browser cookies. Deleting a cookie
alone is insufficient because a copied cookie could remain usable.
The optional JSON `scope` is `current` by default. `others` revokes every
session owned by the user except the calling session and preserves its cookies;
`all` revokes every session, including the caller, and clears its cookies.

Browser logout and OAuth2 token revocation are separate operations. User
deactivation and deletion perform broader cleanup, but a normal logout does not
implicitly revoke every OAuth2 token.

Session resolution and logout adapters record cookie intentions on the request
rather than mutating an injected response. Login is the only adapter that
writes newly issued credentials directly to the response it returns. One
middleware applies every later intent to the actual HTML, redirect, or JSON
response and replaces any conflicting session-owned `Set-Cookie` header.
Clearing authenticated state is terminal: a later refresh cannot restore it.
The CSRF initializer has one explicit combined operation that clears stale
authenticated state while issuing fresh anonymous CSRF state.

## Trust Assumptions And Common Mistakes

- TLS protects credentials and cookies in transit.
- Proxy, trusted-host, and public-origin settings represent the external URL.
- Session identifiers are random and stored using hashed lookup values.
- Current user and organization state comes from the canonical SQLAlchemy identity
  database, not from browser input.
- A session cookie is not an OAuth2 access token.
- `SameSite` alone is not a complete CSRF policy.
- A `204` login response is not a failure; authentication state is carried by
  the cookie and configured CSRF transport.

Browser sessions always use SQLAlchemy. This keeps user lifecycle changes,
session revocation, and related OAuth2 revocation inside one relational
transaction.

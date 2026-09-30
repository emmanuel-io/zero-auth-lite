# Error Reference

## Startup Configuration Errors

Settings validation rejects unknown fields and unsupported feature combinations
before the server starts. Treat an unusable SQLite path, OIDC without its
authorization-code/JWKS prerequisites, or interactive grants without browser
sessions as deployment configuration errors.

Application dependencies raise `RuntimeError` only if required configuration
or request state is incomplete. `create_app()` stores the immutable settings
snapshot on the application; request dependencies own database sessions and
focused service construction.

## OAuth2 Protocol Errors

OAuth2 endpoints return RFC-style error names such as `invalid_request`,
`invalid_client`, `invalid_grant`, `authorization_pending`, and `slow_down`.
Clients must use the protocol error field rather than parsing human-readable
descriptions. Unexpected protocol failures use `500 server_error`; transient
SQLite contention uses `503 temporarily_unavailable` with `Retry-After`.

## JSON Session And Application Errors

Session services raise server exceptions for invalid credentials, invalid or
expired sessions, CSRF failures, and account state. On application-owned JSON
routes, FastAPI handlers translate application domain errors,
request-validation errors, and plain `HTTPException` responses into the same
envelope:

```json
{
  "code": "UNAUTHORIZED",
  "message": "Unauthorized operation.",
  "details": []
}
```

`code` is the stable machine-readable value, `message` is a safe human-readable
explanation, and `details` contains structured explanations when a request has
specific violations. Each application error class owns its status, code,
message, and static response headers. The
runtime handler and the OpenAPI response examples consume those same values so
the documented contract matches the serialized response.

On application-owned routes, Bearer access-token verification and persisted
OAuth2-session failures are normalized to the application code `UNAUTHORIZED`.
The OpenID Connect UserInfo endpoint translates both categories to the protocol
error `invalid_token` instead.

External OAuth2 interaction routes use
`400 OAUTH2_INTERACTION_INVALID` for missing, expired, consumed, or
user/organization-mismatched handles. This deliberately prevents the frontend
from distinguishing whether an opaque handle ever existed. Interaction,
session, and CSRF responses carry `Cache-Control: no-store`.

Request validation uses the application code `VALIDATION`. Its details contain
only a value location, a safe message, and the Pydantic validation type. Raw
input values and validation context are not returned because they may contain
sensitive or non-serializable data:

```json
{
  "code": "VALIDATION",
  "message": "Request validation failed.",
  "details": [
    {
      "location": ["body", "email"],
      "message": "Field required",
      "type": "missing"
    }
  ]
}
```

## Browser Presentation Errors

Built-in browser routes render failures as safe HTML rather than returning the
JSON envelope. This applies to authentication pages, OAuth2 interaction pages,
and the `/management/organization` and `/management/operator` management interfaces. Management requests
initiated by htmx receive an HTML fragment suitable for the current page.

Missing or invalid management authentication redirects to the configured login
entry point. OAuth2 protocol endpoints remain separate: they return their
standard protocol errors even when a browser initiated the request.

Routes list the concrete application errors they expose. When several errors
share one HTTP status, OpenAPI groups them under that response. Its example
keys only distinguish documentation examples; clients use the `code` inside
the payload. Declared response headers are included in the same contract.
Invalid user-list date ranges return `400 START_DATE_AFTER_END_DATE`. Removing
an organization's final active, verified administrator returns
`409 LAST_ACTIVE_ORGANIZATION_ADMIN`.

SQLite unique, check, foreign-key, and not-null failures that do not represent
a recognized domain conflict use the stable application code `DATA_CONFLICT`
and the generic message `The requested data conflicts with stored data.` A
known collision between active normalized email addresses uses
`ALREADY_EXISTS`, including when the database constraint resolves a concurrent
ownership race. In `development`, `DATA_CONFLICT` details may contain one safe
diagnostic whose type is `unique_violation`, `check_violation`,
`foreign_key_violation`, or `not_null_violation`. Its location is empty because
a relational constraint does not necessarily identify one HTTP field. These
diagnostics never contain SQLite messages or table, column, and constraint
names.

In `deployment`, persistence diagnostics are redacted and `details` is empty.
Validation details remain available so clients can correct invalid requests.
Clients must therefore branch only on `DATA_CONFLICT`; a persistence detail is
diagnostic information and is not a stable deployment contract.

OAuth2 protocol errors remain separate and retain their RFC-style
`{"error": ...}` contract.

Authentication failures preserve their `WWW-Authenticate` challenge. CSRF
failures use `403`, while absent or invalid authentication uses `401`. Browser
session failures return the `Session` challenge, bearer failures return the
`Bearer` challenge, and a request with no credentials advertises every enabled
application authentication transport (`Bearer, Session` when both are enabled).
Transient SQLite lock failures include `Retry-After`.

CSRF error codes distinguish the rejected proof component. In particular,
`CSRF_REQUEST_SOURCE_MISSING` means neither `Origin` nor `Referer` was present,
while `CSRF_REQUEST_SOURCE_UNTRUSTED` means the supplied request source was
malformed or outside the configured trusted origins. Token-cookie divergence
continues to use `CSRF_COOKIE_HEADER_MISMATCH`.

Do not log raw passwords, session cookies, authorization codes, access tokens,
refresh tokens, client secrets, or single-use workflow tokens when handling
errors.

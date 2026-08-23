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
descriptions.

## Session And Application Errors

Session services raise server exceptions for invalid credentials, invalid or
expired sessions, CSRF failures, and account state. FastAPI handlers translate
these into HTTP responses. Application domain errors, request-validation
errors, and plain `HTTPException` responses use the same envelope:

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

Bearer access-token verification and persisted OAuth2-session failures use the
application code `INVALID_ACCESS_TOKEN`. Standardized OAuth2 and OIDC endpoints
translate both categories to the protocol error `invalid_token` instead.

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

Routes list the concrete application errors they expose. When several errors
share one HTTP status, OpenAPI groups them under that response. Its example
keys only distinguish documentation examples; clients use the `code` inside
the payload. Declared response headers are included in the same contract.
Invalid user-list date ranges return `400 START_DATE_AFTER_END_DATE`. Removing
an organization's final active, verified administrator returns
`409 LAST_ACTIVE_ORGANIZATION_ADMIN`.

SQLite unique, check, foreign-key, and not-null failures all use the stable
application code `DATA_CONFLICT` and the generic message `The requested data
conflicts with stored data.` In `development`, `details` may contain one safe
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
`Bearer` challenge, and transient SQLite lock failures include `Retry-After`.

Do not log raw passwords, session cookies, authorization codes, access tokens,
refresh tokens, client secrets, or single-use workflow tokens when handling
errors.

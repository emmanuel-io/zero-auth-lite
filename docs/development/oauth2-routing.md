# OAuth2 Routing Guide

Use this guide when changing routes under `/oauth2/*`.

The architectural rule is recorded in the ADR
[Preserve typed FastAPI parameters on OAuth2 protocol routes](architecture/adr-oauth2-typed-fastapi-parameters.md).

## Core Pattern

Keep typed FastAPI request extraction on protocol routes and translate
`RequestValidationError` at the OAuth2 route boundary.

Do not delete typed `Query`, `Form`, `Header`, `Cookie`, `Security`, or
dependency parameters just to suppress FastAPI `422` responses.

## Route Boundary

Zero Auth Lite scopes protocol-validation translation through the custom route class
in `app/oauth2/protocol_route.py`.

`OAuth2ProtocolRoute` is applied to OAuth2 routers such as:

- `app/oauth2/authorization/router.py`
- `app/oauth2/devices/router.py`
- `app/oauth2/routers/tokens.py`

It catches FastAPI `RequestValidationError` and maps it to OAuth2 errors
without changing application APIs outside the protocol routers.

Authorization redirect safety remains a separate concern. The authorization
endpoint must validate the client and redirect URI before redirecting protocol
errors back to a client.

## Typed Transport Extraction

### Authorization Request

Authorization request parameters belong in `Query` fields or a typed query
dependency:

```python
class AuthorizationRequestParams:
    def __init__(
        self,
        response_type: Annotated[Literal["code"], Query()],
        client_id: Annotated[str, Query(min_length=1)],
        redirect_uri: Annotated[AnyUrl, Query()],
        code_challenge: Annotated[str, Query(pattern=r"^[A-Za-z0-9_-]{43,128}$")],
        code_challenge_method: Annotated[Literal["S256"], Query()],
        scope: Annotated[str | None, Query()] = None,
        state: Annotated[str | None, Query()] = None,
        nonce: Annotated[str | None, Query()] = None,
    ) -> None: ...
```

Adapt exact PKCE constraints to the current policy, but keep them typed and
visible in the route contract.

### Token Form

Token request parameters belong in
`application/x-www-form-urlencoded` `Form` fields:

```python
class TokenRequestForm:
    def __init__(
        self,
        grant_type: Annotated[OAuth2GrantType, Form()],
        client_id: Annotated[str | None, Form()] = None,
        client_secret: Annotated[str | None, Form()] = None,
        code: Annotated[str | None, Form()] = None,
        redirect_uri: Annotated[str | None, Form()] = None,
        code_verifier: Annotated[str | None, Form()] = None,
        refresh_token: Annotated[str | None, Form()] = None,
        device_code: Annotated[str | None, Form()] = None,
        scope: Annotated[str | None, Form()] = None,
    ) -> None: ...
```

Grant-specific conditional rules still belong in domain parsing and services,
not in a giant endpoint signature.

### Revocation And Introspection

Revocation and introspection requests keep these fields in the form body:

- `token`
- `token_type_hint`
- `client_id`
- `client_secret`

Never move any of these into query parameters.

Explicitly prohibited:

- `client_secret` in the query string
- `token` in the query string
- `Authorization` data in the query string

### Browser Decisions

Browser POST routes keep typed forms:

- `POST /oauth2/authorize`: the same authorization request as GET, encoded as a form
- `POST /oauth2/authorize/decision`: `transaction_id`, `decision`, and optional
  `csrf_token` when an HTML form is used instead of the configured header

State-changing browser forms must continue to use existing browser-session and
CSRF dependencies. Device verification remains typed inside the built-in web
adapter. It is not an OAuth2 protocol endpoint, but it remains visible in the
application OpenAPI document when the built-in OAuth2 UI is mounted.
Authorization transactions are server-side, user-bound before consent,
organization-bound, expiring, and single-use. Never put editable authorization
request fields in the decision form.

### Client Authentication

HTTP Basic client authentication should use a typed `Security` or header
dependency so the OpenAPI security scheme remains defined and discoverable.

If body-based client authentication is also supported, its credentials remain
in form data. Secrets must never move into query strings.

### Raw Request Access

Raw `Request` access is allowed only when the route genuinely needs request URL
details, request state, response header control, or another documented
framework-level concern.

One such concern exists for optional OAuth2 client credentials. Typed optional
form extraction maps both a missing value and `client_secret=` or `client_id=`
to `None`, but authentication policy must treat an explicitly empty credential
as supplied. Client-authentication dependencies may reread only those fields
from the cached form body when the typed value is `None`. Typed `Form`
parameters remain authoritative for non-empty values, route signatures, and
OpenAPI.

It is not an acceptable substitute for typed protocol parameters.

## OpenAPI Expectations

Typed FastAPI parameters are the primary source of protocol OpenAPI.

Apply the shared limits from `OAuth2Specs` to typed form/query parameters and
their domain DTOs. This keeps oversized requests from crossing a persistence
boundary whose columns have stricter limits. The OAuth2 route class translates
these transport validation failures into protocol `400` responses.

Use targeted OpenAPI adjustments only when FastAPI cannot accurately express a
detail such as:

- removing unreachable protocol `422` responses;
- defining protocol-specific response metadata;
- documenting security schemes that must remain aligned with typed runtime
  extraction.

Do not replace typed runtime parameters with a handwritten schema.

## OAuth2 Agent Checklist

### Transport Contract

- Are query parameters still typed?
- Are form parameters still typed?
- Are headers represented as headers or security dependencies?
- Are cookies represented through cookie or session dependencies?
- Are credentials absent from query strings?
- Does every state-changing browser form remain CSRF-protected?

### Protocol Errors

- Can any malformed protocol request return FastAPI `422`?
- Does validation become `OAuth2ErrorResponse`?
- Are invalid clients handled with the correct status and headers?
- Does authorization redirect only after validating the client and redirect
  URI?

### OpenAPI

- Does every endpoint expose its real input?
- Is every referenced security scheme defined?
- Are form bodies represented as `application/x-www-form-urlencoded`?
- Is the password grant absent?
- Are protocol `422` responses absent?
- Are browser HTML responses documented as `text/html`?
- Are redirects documented with `Location`?

### Runtime And Generated Contract Alignment

- Do typed dependency fields match the generated OpenAPI schema?
- Are supported grant enums identical in code and OpenAPI?
- Are conditional grant fields validated after transport extraction?
- Do OpenAPI tests fail if a request body or parameter disappears?

## Review Checklist

Any change touching `/oauth2/*`, OAuth2 router dependencies, OAuth2 request
models, OAuth2 exception handling, or OAuth2 OpenAPI generation must include:

- runtime protocol-error tests;
- OpenAPI contract tests;
- confirmation that typed parameters remain;
- confirmation that credentials remain outside query strings;
- confirmation that no OAuth2 protocol operation advertises `422`.

Reviewers should reject changes that "simplify" endpoint signatures by moving
typed fields into raw request parsing without a demonstrated and documented
need.

# Preserve Typed FastAPI Parameters On OAuth2 Protocol Routes

Zero Auth Lite keeps typed FastAPI request extraction on OAuth2 and OIDC protocol
routes. This is a deliberate architectural choice, not an incidental framework
detail.

## Status

Accepted.

## Context

Parsing protocol requests manually to avoid FastAPI-generated `422
Unprocessable Entity` responses would break important protocol and
documentation behavior:

- OpenAPI query parameters disappeared from `/oauth2/authorize`;
- form request bodies disappeared from `/oauth2/token`, `/oauth2/revoke`,
  `/oauth2/introspect`, and device-flow routes;
- revocation and introspection credentials became harder to represent safely;
- Swagger and generated clients could not discover how to call the protocol
  endpoints;
- endpoint contracts became less explicit and less readable.

## Decision

OAuth2 and OIDC protocol routes must use typed FastAPI request extraction
through the transport source that matches the protocol field:

- authorization request parameters: `Query`
- token request parameters: `Form`
- revocation request parameters: `Form`
- introspection request parameters: `Form`
- device authorization parameters: `Form`
- browser consent decisions: `Form`
- device approval and denial: `Form`
- HTTP Basic client authentication: `Security` or a typed header dependency
- browser session authentication: cookie or session dependency
- bearer access tokens: typed bearer security dependency
- grouped parameter objects: typed dependency classes or typed Pydantic models

Typed parameters stay in the route contract because they provide:

- explicit router signatures;
- static typing and readable call sites;
- transport-level validation;
- discoverable OpenAPI parameters and form bodies;
- generated client compatibility;
- usable Swagger interactions;
- a clear separation between transport parsing and domain validation.

## Validation Error Strategy

OAuth2 protocol routes must not expose FastAPI `422` validation responses to
protocol clients.

Instead, FastAPI `RequestValidationError` must be translated at the OAuth2
router boundary through a narrowly scoped mechanism such as the custom
`OAuth2ProtocolRoute` in `app/oauth2/protocol_route.py`.

That boundary must:

- apply only to OAuth2 and OIDC protocol routes;
- convert validation failures to `OAuth2ErrorResponse`;
- normally return `400 invalid_request`;
- return other OAuth2 errors when protocol semantics require them, such as
  `unsupported_grant_type`;
- avoid leaking Pydantic validation structures to OAuth2 clients;
- preserve normal `422` behavior for application APIs outside the protocol
  routers;
- handle authorization-endpoint redirect safety separately from direct token
  endpoint errors.

## Rejected Workaround

The project explicitly rejects replacing typed request extraction with raw
request parsing merely to avoid FastAPI validation:

```python
async def endpoint(request: Request):
    form = await request.form()
```

Raw request access remains acceptable only for narrow, documented needs such
as:

- reading the original URL;
- computing issuer-aware redirects;
- handling content-type details not exposed by typed dependencies;
- accessing request state;
- integrity-bound authorization transaction handling;
- working around a documented framework limitation.

Raw parsing must not replace the canonical typed parameter contract.

### Empty Client-Credential Presence

FastAPI's typed extraction for an optional form string presents both a missing
field and an explicitly empty field as `None`. OAuth2 client authentication must
distinguish those cases: a public client that omits `client_secret` is valid,
while a client that submits `client_secret=` has attempted a credential method
and must be rejected.

Zero Auth Lite therefore rereads only `client_id` and `client_secret` from the cached
form body when their typed values are `None`. This is a narrow framework-level
exception that preserves field presence. The typed `Form` parameters remain in
the dependency signature and remain the source of the generated OpenAPI request
body. Raw form access does not parse grant payloads, replace typed validation,
or move credentials outside `application/x-www-form-urlencoded` bodies.

## Router Versus Service Validation

Transport extraction and protocol-domain validation solve different problems.

FastAPI typing handles:

- transport extraction;
- required versus optional fields;
- simple type conversion;
- fixed literals and enums;
- syntax and length constraints;
- basic URI formatting.

OAuth2 services and domain helpers handle:

- grant-specific conditional requirements;
- client authentication policy;
- redirect URI registration and exact matching;
- PKCE verification;
- authorization-code consumption;
- token state and rotation;
- scope policy;
- organization-scope enforcement;
- user state;
- protocol state transitions.

Do not move the entire OAuth2 protocol into route signatures.

Do not delete typed transport parameters because deeper domain validation is
still required.

## OpenAPI Strategy

Typed FastAPI parameters are the primary source of OAuth2 and OIDC OpenAPI.

Custom OpenAPI adjustments are allowed only when the generated schema needs a
focused protocol correction, for example:

- removing unreachable auto-generated `422` responses from protocol routes;
- representing protocol-specific response headers;
- documenting conditional authentication or grant-shape limitations that
  FastAPI cannot express directly.

OpenAPI overrides must complement typed runtime parameters, not replace them.

Do not maintain handwritten request schemas that can drift away from the route
signatures unless a focused regression test compares them.

## Consequences

This decision keeps some route signatures verbose and requires a custom
protocol-validation boundary plus a few OpenAPI adjustments.

That complexity is preferable to an undocumented, untyped, or misleading
protocol surface.

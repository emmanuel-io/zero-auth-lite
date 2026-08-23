---
name: oauth2
description: Work on OAuth2 flows, grants, token lifecycle, and related documentation for Zero Auth Lite.
---

# OAuth2 Skill

## Purpose

Implement OAuth2 in a readable, educational, and reusable way.

Zero Auth Lite should make OAuth2 flows understandable to developers who know FastAPI but may not deeply understand OAuth2.

## Principles

- Keep OAuth2 concepts visible.
- Prefer explicit flow steps over hidden abstractions.
- Each grant should explain why it exists.
- Each grant should expose the security assumptions behind it.
- Avoid framework magic.
- Avoid enterprise IAM scope creep.
- Keep typed FastAPI request extraction visible on protocol routes.
- Treat generated OpenAPI as part of the public protocol contract.

## Supported Grants

The project supports:

- Authorization Code with PKCE;
- Client Credentials;
- Device Code;
- Refresh Token;
- Token revocation;
- Token introspection.

Do not add password, implicit, hybrid, dynamic client registration, PAR, JAR,
DPoP, or token exchange.

## Documentation Requirements

For every OAuth2 grant, document:

- why the grant exists;
- which actors participate;
- what problem it solves;
- where the user is authenticated;
- where authorization is granted;
- how tokens are issued;
- common misconceptions.

## Common Misconception To Address

The authorization code does not authenticate the user.

The user must already have been authenticated before the authorization code is issued.

The code is a temporary artifact allowing a client to obtain tokens without seeing the user's credentials.

## Implementation Guidance

Grant handlers should remain small.

Avoid building a generic OAuth2 framework too early.

Prefer clear domain objects and explicit validation steps.

Good names matter more than clever abstractions.

Never remove typed `Query`, `Form`, `Header`, `Cookie`, `Security`, or
dependency parameters from OAuth2 and OIDC protocol routes just to avoid
FastAPI `422` responses.

Translate `RequestValidationError` at the OAuth2 protocol route boundary
instead.

Never move client secrets, bearer material, or tokens into query parameters.

Do not replace typed request extraction with raw `request.form()` or query
parsing unless a documented framework limitation makes that unavoidable.

Do not remove OpenAPI request bodies or parameters as a side effect of protocol
error handling.

Do not add the password grant merely to fit FastAPI helper classes.

OAuth2 changes are not complete until both runtime protocol-error tests and
OpenAPI contract tests pass.

Keep GET and form POST authorization requests on `/oauth2/authorize`. Keep the
CSRF-protected consent decision on `/oauth2/authorize/decision`, backed by a
server-side, user-bound, expiring, single-use transaction.

Require PKCE S256 for every authorization code and preserve conditional public
versus confidential client authentication. Protocol routes must not return or
advertise `422`; generated FastAPI OpenAPI remains the primary contract.

Do not claim protocol certification without recorded external conformance
results.

See:

- `docs/development/architecture/adr-oauth2-typed-fastapi-parameters.md`
- `docs/development/oauth2-routing.md`

## Non-Goals

Do not add:

- SAML;
- SCIM;
- LDAP;
- enterprise identity provider behavior;
- social login;
- complex provider federation;
- production-grade abuse protection.

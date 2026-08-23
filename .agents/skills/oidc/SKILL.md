---
name: oidc
description: Work on OpenID Connect discovery, JWKS, ID tokens, UserInfo, and related documentation.
---

# OpenID Connect Skill

## Purpose

Implement OIDC as the identity layer on top of OAuth2.

Zero Auth Lite should help developers understand the difference between OAuth2 authorization and OIDC identity.

## Principles

- Keep OIDC minimal and readable.
- Explain what OIDC adds to OAuth2.
- Make issuer, subject, audience, claims, and signing explicit.
- Avoid hiding ID token creation behind opaque helpers.

## Supported Concepts

The project may demonstrate:

- Discovery endpoint;
- JWKS endpoint;
- ID tokens;
- UserInfo endpoint;
- subject identifiers;
- standard claims;
- signing keys;
- issuer metadata.

## Documentation Requirements

OIDC documentation should answer:

- what OAuth2 does not provide by itself;
- why ID tokens exist;
- how ID tokens differ from access tokens;
- what UserInfo is for;
- how JWKS is used;
- why issuer consistency matters.

## Implementation Guidance

Keep OIDC helpers small.

Token signing should be explicit and testable.

Avoid supporting unnecessary claim complexity in early versions.

Prefer readable examples over exhaustive protocol coverage.

Require Bearer security on GET and POST UserInfo. Require `openid`, return
`sub`, and select optional claims from granted `profile` and `email` scopes.

Derive OIDC discovery from the configured issuer independently from OAuth
authorization-server metadata path construction. Require `jwks_uri`, publish a
unique `kid` for every verification key, and keep token/discovery issuers
identical.

Do not advertise implicit or hybrid responses. Do not claim certification
without recorded external conformance results.

## Non-Goals

Do not add:

- advanced federation;
- enterprise discovery extensions;
- identity brokering;
- social login;
- SAML compatibility;
- complex account linking.

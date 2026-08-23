# Trust Boundaries

## Browser And Client Input

Passwords, cookies, bearer tokens, redirect URIs, scopes, PKCE values, device
codes, and CSRF headers are untrusted input. Parsing a value does not establish
its authenticity or authorization.

Password hashing and verification are deliberately executed through an async
worker-thread boundary. The synchronous Argon2 provider remains an application
dependency, but its CPU-bound work must never run on the request event loop.

## Application Identity Boundary

Zero Auth Lite trusts its application-owned SQLAlchemy models, focused mapping
helpers, and identity services to return current user, organization, password-hash,
role, and lifecycle state. A faulty join, missing organization predicate, or invalid
ORM-to-DTO mapping can authenticate the wrong account or cross an organization
boundary.

## Persistence And Transaction Boundary

The request-scoped SQLAlchemy `AsyncSession` owns durable authentication state.
Services rely on database constraints and explicit conditional statements to
preserve one-time use, expiry, uniqueness, rotation, and revocation behavior.
Security-sensitive identity changes, session revocation, OAuth2 token-family
revocation, and outbox writes must remain in the same transaction when they
form one lifecycle decision.

## Proxy And Origin Boundary

Host, scheme, and source IP may be rewritten by a proxy. Trust forwarded
values only from configured proxy addresses. Public origins affect cookies,
CSRF, discovery, issuer validation, redirect URIs, and links sent to users.

## Signing Boundary

The authorization server holds private signing keys. Clients and resource
servers receive only public keys. Anyone with the private key can create tokens
that pass signature verification, so key access is equivalent to issuer
authority.

## Application Authorization Boundary

An authenticated principal does not imply access to every resource. The
application must enforce organization, role, permission, scope, and ownership checks
after Zero Auth Lite establishes identity.

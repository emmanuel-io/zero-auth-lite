# Zero Auth Lite

Zero Auth Lite is a readable FastAPI authentication and identity server.

Its purpose is to help Python developers understand, test, and adapt
authentication and authorization concepts through clear code and a runnable
canonical server.

## Primary Goal

Make user management, AuthN, AuthZ, OAuth2, and OpenID Connect understandable.

By combining user lifecycle management with OAuth2 and OpenID Connect, Zero
Auth acts as a minimal, educational identity provider (IdP).

Zero Auth Lite should feel like executable documentation.

When making changes, optimize for:

- readability;
- explicit behavior;
- small modules;
- understandable security decisions;
- explicit user lifecycle behavior;
- a runnable canonical server;
- documentation that explains why things exist.

## Non-Goals

Zero Auth Lite is not:

- an enterprise IAM platform;
- a Keycloak replacement;
- an Auth0 alternative;
- a SaaS auth provider;
- a full production identity platform;
- a generic application framework.

Do not add:

- SAML;
- SCIM;
- LDAP;
- social login;
- multi-database organization isolation;
- Kubernetes deployment;
- built-in request rate limiting;
- complex observability stacks;
- enterprise administration features.

## Architecture Principles

- Prefer explicit code over magic.
- Prefer readable flows over clever abstractions.
- Prefer protocol-based extension points over inheritance-heavy designs.
- Prefer small modules organized by authentication concepts.
- Keep feature boundaries explicit inside the canonical server.
- Keep top-level application composition in `app/main.py`.
- Keep application-owned JSON endpoints under a versioned `/api/v1` contract.
- Keep standardized OAuth2 and OIDC protocol endpoints under `/oauth2` and
  issuer-derived discovery paths.
- Let feature modules own their domain behavior, routes, dependencies, and
  persistence adapters.
- Keep database, settings, identity models, migrations, and application
  lifecycle management inside the canonical server.

## Database Boundary

SQLite is the only supported database for the canonical server. SQLAlchemy is
used to keep relational persistence readable and composable, not to promise
portability to PostgreSQL or other database engines.

- Evaluate transactions, locking, concurrency, migrations, and performance
  according to SQLite's behavior.
- Preserve the canonical WAL, busy-timeout, foreign-key, synchronous, and
  explicit-transaction settings unless a measured problem justifies a
  documented change.
- Prefer short write transactions, database constraints, conditional
  mutations, bounded cleanup batches, and query plans verified against
  SQLite.
- Never use implicit SQLAlchemy relationship lazy loading. Declare ORM
  relationships with `lazy="raise"` and load required related data explicitly
  in the owning query.
- Do not add cross-database compatibility layers or make review findings based
  only on behavior from another database engine.
- Keep backup and restore outside the implementation until that work is
  requested explicitly, while avoiding designs that would make a consistent
  SQLite backup unnecessarily difficult.

## User Management

User management is part of the canonical server and is one of the capabilities
that makes Zero Auth Lite an identity provider rather than only a token issuer.

It includes:

- registration and invitations;
- user profiles and account self-service;
- email verification and password reset;
- activation, deactivation, and deletion;
- organization membership and organization administration;
- explicit operator and organization-admin roles;
- browser-session and OAuth2-session revocation after security-sensitive
  account changes.

Keep user management focused on identity and access concerns. It is not generic
application CRUD, HR lifecycle management, identity governance, or enterprise
directory administration.

## OAuth2 Route Contract

- Never remove typed FastAPI OAuth2 `Query`, `Form`, `Header`, `Cookie`,
  `Security`, or dependency parameters to avoid automatic `422` responses.
- Preserve the typed transport contract and translate `RequestValidationError`
  through the OAuth2 protocol route boundary.
- Never move OAuth2 client secrets or tokens into query parameters.
- Never convert a typed OAuth2 form or query endpoint to unrestricted raw
  request parsing without a documented framework limitation.
- Never remove OpenAPI request bodies or parameters as a side effect of
  protocol-error handling.
- Never introduce the resource-owner password grant merely to satisfy FastAPI
  helper classes.
- Never reference an undefined OpenAPI security scheme.
- OAuth2 changes require both runtime protocol-error tests and OpenAPI
  contract tests.

## Canonical Server Boundary

Zero Auth Lite is one configurable authentication and authorization server.

The canonical server owns:

- FastAPI application creation and lifespan management;
- settings and feature flags;
- database setup and Alembic migrations;
- user and organization models and lifecycle management;
- AuthN and AuthZ behavior;
- OAuth2 and OIDC protocol flows;
- browser sessions, CSRF, and token handling;
- API and protocol routers;
- local Docker Compose and environment configuration.

Request rate limiting is a deployment-hardening responsibility outside the
canonical server. Documentation should tell operators to add it at a trusted
reverse proxy, gateway, or equivalent boundary when the server is exposed to
untrusted traffic.

Feature folders should keep related domain behavior, HTTP dependencies, routes,
and persistence adapters together. `app/main.py` should only compose top-level
surfaces such as `/oauth2`, `/api`, and `/health` according to the enabled
settings. The versioned API composer mounts browser-session JSON transport
under `/api/v1/sessions`.

The server should remain directly understandable, without extra composition,
installation, or compatibility layers.

## Documentation Philosophy

Documentation should explain:

- why a flow exists;
- what problem it solves;
- which actors participate;
- where authentication happens;
- where authorization happens;
- how user lifecycle changes affect sessions, tokens, and access;
- what security assumptions exist;
- common misconceptions.

OAuth2 and OIDC should not feel like magic.

## Agent Skills

Project-specific skills live in `.agents/skills/`.

When working on OAuth2, OIDC, AuthN, AuthZ, SQLite persistence, or
documentation, read the matching `.agents/skills/*/SKILL.md` before making
changes.

## Coding Style

Use Python 3.12+.

Use:

- FastAPI;
- Pydantic v2;
- SQLAlchemy 2 style for relational persistence;
- `Mapped[...]` for SQLAlchemy models;
- `Annotated[..., Depends(...)]` for FastAPI dependencies;
- `type | None` instead of `Optional[type]`;
- Protocols over ABCs unless an ABC is clearly justified;
- Google-style docstrings for files, classes, functions, and methods.

Keep function and method arguments on a single line when practical.

Prefer `orjson` over `json` for application JSON serialization where relevant.

## Testing

Tests should verify behavior, not implementation details.

Important flows should be tested end-to-end where possible:

- registration and invitation;
- login;
- logout;
- email verification;
- password reset;
- profile updates and account deletion;
- organization-scoped and operator user administration;
- authorization code;
- PKCE;
- client credentials;
- device code;
- refresh tokens;
- OIDC discovery;
- JWKS;
- UserInfo.

## Decision Rule

When uncertain, choose the option that makes user management, OAuth2, OIDC,
AuthN, or AuthZ easier to understand.

For OAuth2 routing details and rationale, see
`docs/development/architecture/adr-oauth2-typed-fastapi-parameters.md` and
`docs/development/oauth2-routing.md`.

## Change Discipline

Do not change working code merely because another design is possible.

Do not propose or implement:

- speculative refactors;
- abstraction for hypothetical future requirements;
- style-only rewrites;
- architectural changes without a concrete problem;
- optional features outside the documented scope.

When reviewing the repository, classify findings as:

- release blocking;
- concrete maintenance or correctness issue;
- optional improvement.

Optional improvements should not be implemented unless explicitly requested.
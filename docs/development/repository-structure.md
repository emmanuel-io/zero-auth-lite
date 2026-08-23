# Repository Structure

```text
.
├── app/
│   ├── main.py                 # Canonical FastAPI entrypoint
│   ├── browser_sessions/       # Browser sessions, CSRF, cookies, and services
│   ├── oauth2/                 # OAuth2/OIDC flows, including user_authorizations
│   ├── auth_tokens/            # Single-use verification/reset token lifecycle
│   ├── bootstrap/              # First-run operator creation and process lock
│   ├── events/                 # Durable notification outbox and worker
│   ├── web/                    # Optional built-in Jinja browser presentation
│   ├── identity/               # Identity DTOs, registration, services, and persistence mapping
│   ├── password/               # Password hashing protocol and implementation
│   ├── api/                    # Versioned self-service and administration APIs
│   ├── security/               # AuthN/AuthZ composition and session_revocation
│   ├── core/                   # Shared errors, request helpers, logging, and primitives
│   ├── db/                     # SQLite engine, ORM models, and session setup
│   ├── mail/                   # Email rendering and SMTP delivery
│   └── settings/               # Server settings
├── tests/
│   ├── routes/                 # Black-box HTTP tests using the canonical app lifespan
│   ├── app/                    # Feature-level service, router, and contract tests
│   ├── fixtures/               # Shared canonical-app and protocol test setup
│   └── docs/                   # Executable documentation and snippet tests
├── docs/
│   ├── getting-started/       # Installation, initial configuration, first client
│   ├── guides/                # OAuth2, OIDC, sessions, users, and organizations
│   ├── operations/            # Deployment, persistence, workers, and security
│   ├── reference/             # Public settings, routes, and error contracts
│   └── development/           # Internals, architecture, tests, and contribution
├── alembic/                    # Relational schema migrations for the canonical server
├── alembic.ini                 # Alembic entrypoint configuration
├── config/
├── compose.yaml
└── pyproject.toml
```

## Canonical Server Boundary

Zero Auth Lite is organized as one configurable authentication and authorization
server. Feature folders own their domain behavior, HTTP dependencies, routes,
and persistence. `app/main.py` is the server entrypoint: it attaches stable
app state, always mounts the identity-management baseline, and composes the
configured authentication and protocol mechanisms.

Identity workflows, auth-token processing, identity and organization
administration, and outbox dispatch are permanent server capabilities. Browser
sessions, OAuth2, OIDC, and JWKS are configurable mechanisms. The built-in
workflow HTML pages are an optional presentation layer controlled by
`ui.authentication`; authorization roles, permissions, and access checks
remain part of the permanent baseline.

`app/security/authentication.py` composes browser-session and OAuth2
authentication into canonical principal contexts.
`app/security/authorization.py` owns the FastAPI dependencies that enforce
roles, permissions, and OAuth2 scopes. The package also owns the transactional
`session_revocation` boundary that invalidates browser and OAuth2 sessions
together. Feature-neutral constant-time
comparison helpers remain under `app/core/compare.py`; `core` does not compose
feature implementations.

Authorization has two deliberate layers. FastAPI dependencies enforce the
complete HTTP contract: required roles, application permissions, OAuth2 scopes,
and CSRF proof where applicable. Actor-bound services repeat the role check so
their domain entry points cannot be called with the wrong kind of actor, then
enforce resource ownership, organization boundaries, and lifecycle invariants.
Service role checks do not replace route permission or scope checks.

Black-box HTTP behavior is tested under `tests/routes/` with HTTPX, the real
FastAPI lifespan, and isolated migrated databases. Tests under `tests/app/`
exercise feature-level services, routers, validation, and generated
OpenAPI contracts without claiming ownership of the black-box route surface.
Reusable setup and test-data builders live under `tests/fixtures/`.

`app/api/v1/` is not generic application CRUD. It is the minimal identity and
organization administration surface needed to operate the authentication server:
current profile, organization identities, current organization metadata, and,
when at least one grant is enabled, OAuth2 client administration.

Server-operator OAuth2 client administration is composed from separate route
modules for registry operations, credential rotation, user-organization access,
and machine-organization access. Their URLs remain under
`/api/v1/admin/oauth2/clients`.

Route ownership follows a simple mount rule:

- `app/main.py` mounts only top-level server surfaces such as `/oauth2`,
  `/api`, `/health`, and the settings-driven built-in web UI.
- `app/web/` owns HTML adapters and assets, while authentication and protocol
  services continue to own validation and business behavior.
- `app/api/v1/` contains only versioned API modules.
- App-owned auth workflows that may evolve belong under `/api/v1/auth`.
- Current-organization administration routes are grouped in `app/api/v1/organization/`;
  its router composes metadata, user, and optional OAuth2 session administration
  from explicitly named subpackages.
- Browser-session behavior stays in `app/browser_sessions/`; its JSON transport
  adapter lives in `app/api/v1/browser_sessions/`, and the versioned route
  composition belongs to `app/api/v1/router.py`.
- Current-user OAuth2 grant inspection and revocation lives in
  `app/oauth2/user_authorizations/`; its HTTP route remains
  `/api/v1/me/authorizations`.

## Persistence

SQLite is the only supported relational target for the canonical server.
Relational services receive the request-scoped SQLAlchemy session directly.
Browser sessions and OAuth2 state always use SQLAlchemy so related lifecycle
changes can share one transaction.
Canonical ORM rows live in `app/db/models/`, while identity DTOs, criteria,
services, and domain types remain under `app/identity/`. Engine and session
setup also lives in `app/db/`.
Alembic migrations live at the repository root under `alembic/`, and
`app/db/alembic.py` exists only to expose the canonical relational metadata to
that migration tool.

`app/api/v1/auth/` owns the versioned authentication request schemas,
domain-specific endpoint adapters, route paths, and startup-time composition.
Its router mounts registration and new self-registration verification requests
under `auth.registration_enabled`. Verification confirmation remains mounted
for issued tokens, while email changes, password recovery, and invitation
acceptance remain independently available.
`app/identity/registration.py` owns the organization and initial-user transaction,
while `app/auth_tokens/` owns single-use token issuance and confirmation.
`app/events/` persists notification intentions in the request transaction and
builds them after commit, while `app/mail/` owns rendering and SMTP
integration. This keeps HTTP transport, identity lifecycle, token lifecycle,
and delivery infrastructure as explicit boundaries.
`MailService` accepts a narrow provider protocol. SMTP is the canonical shipped
implementation; an embedding application can supply another asynchronous
provider without adding vendor-specific integrations to the server itself.

Feature-local `dtos.py` modules contain service inputs and outputs, all named
with a `DTO` suffix. Services own the SQLAlchemy queries supporting their domain
decisions and do not import `app/api/`. Application-owned HTTP request and
response models live beside their versioned routers under `app/api/v1/` and use
`Request` or `Response` suffixes. Standardized OAuth2 and OIDC protocol routes
retain their protocol-local transport models and typed FastAPI extraction.

OAuth2 grant handlers keep grant-specific authentication, authorization, and
validation visible. Once those decisions are complete,
`app/oauth2/tokens/issuance.py` owns shared token creation, token hashing, new
OAuth2-session persistence, and construction of the standardized token
response. Refresh rotation reuses token creation while retaining its separate
conditional update and family-reuse protections.

## Deliberate Non-Goals

The repository avoids SAML, SCIM, LDAP, social login, provider federation,
enterprise IAM administration, bot or fraud detection, built-in request
limiting, WAF or edge-security systems, and Kubernetes deployment scaffolding.
Those topics would make the auth concepts harder to inspect in a small
reference server.

# Zero Auth Lite

Zero Auth Lite is a readable FastAPI reference server for authentication and
authorization.

It is designed to make browser sessions, user lifecycle management, CSRF,
OAuth2, OpenID Connect, and token lifecycles easier to understand and test.
It is a small educational identity provider, not a turnkey identity platform.

Zero Auth Lite targets prototypes, internal applications, and nominal-load
deployments on one node. High-availability multi-node
deployments are currently out of scope. Request rate limiting belongs at the
deployment boundary and is not implemented by the server.

## Project status: early development

Zero Auth Lite is functional but not yet stable.

APIs, configuration, database schema, and internal interfaces may change
between releases without backward compatibility.

## Documentation

The documentation is organized by purpose:

- [Getting started](docs/getting-started/installation.md): installation,
  initial configuration, and first OAuth2 client.
- [Guides](docs/guides/authentication-and-authorization.md): OAuth2, OIDC,
  sessions, users, and organizations.
- [Operations](docs/operations/deployment.md): deployment, persistence,
  workers, backups, logging, and security.
- Reference: canonical [settings](docs/reference/settings.md),
  [routes](docs/reference/routes.md), and [error](docs/reference/errors.md)
  contracts.
- [Development](docs/development/setup.md): contributor setup, internal
  architecture, tests, conventions, and contribution.

## Server Shape

- `app/main.py` is the canonical FastAPI server entrypoint.
- `app/openapi.py` composes generic, application-security, and OAuth2/OIDC
  OpenAPI policies owned by their respective modules.
- `app/browser_sessions/`, `app/oauth2/`, `app/oauth2/oidc/`, `app/workflow_tokens/`,
  `app/identity/`, and `app/password/` hold the readable auth building blocks
  used by the server.
- `app/api/v1/auth/` owns the versioned registration, verification,
  invitation, and password-recovery HTTP contract. Identity registration lives
  in `app/identity/`, while `app/notifications/` builds durable auth
  notifications and `app/mail/` owns mail transport and template rendering.
- `app/api/v1/organization/` groups current-organization metadata, user administration,
  and optional OAuth2 operations behind one settings-aware router.
- `app/web/` provides the optional built-in Jinja login, consent, device, and
  authentication-email pages without moving behavior out of auth services.
- `/api/v1/organization/users` is organization-scoped and organization-admin-only.
- `app/` also owns settings, database setup, and email delivery. Root-level
  Caddy and Compose files run the local stack.
- `tests/` focuses on behavior: login, logout, grants, discovery, JWKS, and
  other end-to-end auth flows.

## Supported Surface

Zero Auth Lite demonstrates:

- AuthN: registration, login, logout, browser sessions, CSRF, email
  verification, password reset, and session revocation.
- AuthZ: roles, permissions, organization boundaries, OAuth2 scopes, and bearer
  principal resolution.
- Administration: organization-scoped user listing, creation or invitation,
  lifecycle updates through `PATCH`, organization-admin role management, and
  organization-scoped full replacement and deletion through `PUT` and `DELETE`.
- OAuth2 and OIDC: authorization code with PKCE, refresh tokens, client
  credentials, device code, revocation, introspection, discovery, JWKS, ID
  tokens, and UserInfo.

It intentionally does not include SAML, SCIM, LDAP, social login, provider
federation, enterprise IAM administration, bot or fraud detection, WAF or
edge-security systems, built-in request rate limiting, or Kubernetes deployment
templates. Deployments exposed to untrusted traffic must add request limiting
at a trusted reverse proxy, gateway, or other deployment boundary.

The OAuth2/OIDC subset also deliberately excludes password, implicit, hybrid,
dynamic client registration, PAR, JAR, DPoP, and token exchange. Internal
runtime and OpenAPI tests do not constitute external protocol certification;
Zero Auth Lite does not claim OAuth2 or OpenID Connect certification.

## Run Locally

Native execution requires a POSIX operating system because bootstrap operations
use a POSIX file lock. On Windows, use WSL or the Docker Compose stack instead
of running the Python processes directly.

```bash
uv sync --all-groups --all-extras
cp config/development.example.toml zero-auth-lite.toml
uv run alembic upgrade head
uv run uvicorn app.main:create_app --factory --reload --no-access-log --no-proxy-headers
```

Run these commands from the repository root so the server loads the copied
`zero-auth-lite.toml` development profile. Open the UI through
`http://localhost:8000` exactly; the profile intentionally uses non-secure,
host-only cookies for that direct HTTP origin.

In separate terminals from the same directory, run durable event delivery and
OAuth2 persistence cleanup:

```bash
uv run python -m app.notifications.worker
uv run python -m app.browser_sessions.cleanup_worker
uv run python -m app.oauth2.cleanup_worker
```

Open `http://localhost:8000/` for the built-in landing page,
`http://localhost:8000/login` for browser login,
`http://localhost:8000/health/live` for process liveness,
`http://localhost:8000/health/ready` for SQLite readiness, Swagger UI at
`http://localhost:8000/api/docs`, or ReDoc at
`http://localhost:8000/api/redocs`.
The server-rendered authentication forms and interactive JSON adapters are
enabled by default. Set `ZA_UI__IDENTITY_WORKFLOW_MODE=external` when a separate
frontend should replace the built-in forms; use
`ZA_API__INTERACTIVE_AUTH_ROUTES_ENABLED` to control the JSON adapters for sessions,
identity workflows, and external OAuth2 interactions independently. This flag
does not disable the `/me`, `/organization`, or `/server` APIs.
`ZA_UI__MANAGEMENT_AUTHENTICATION` independently
chooses the built-in or external management login, while
`ZA_UI__OAUTH2_INTERACTION` chooses built-in, external, or disabled OAuth2
interaction. See the [built-in UI](docs/guides/builtin-authentication-ui.md)
and [external UI](docs/guides/external-authentication-ui.md) guides for the
required URLs and supported combinations.
The explicit profile disables secure-cookie requirements only for this local
HTTP process. The Compose path below retains the canonical HTTPS defaults.

For the local stack:

```bash
docker compose up --build
```

Mailpit is available through Caddy at
`https://mailpit.localhost:8443`. Caddy exposes the server on
`https://auth.zero-auth-lite.localhost:8443`. Open Swagger UI at
`https://auth.zero-auth-lite.localhost:8443/api/docs` or ReDoc at
`https://auth.zero-auth-lite.localhost:8443/api/redocs`. Compose migrates the shared
database volume before starting the backend and also starts the notification
outbox, browser-session cleanup, and OAuth2 persistence-cleanup workers. Mailpit remains directly
reachable at `http://localhost:8025` for local tooling.

## Development

```bash
./scripts/check.sh test
./scripts/check.sh coverage
./scripts/check.sh ruff
./scripts/check.sh mypy
./scripts/check.sh ty
./scripts/check.sh format
```

The coverage command runs the full test suite with branch coverage, writes the
LCOV data to `reports/coverage/coverage.lcov`, and builds both HTML reports:

- Standard coverage.py HTML: `reports/coverage/html/index.html`
- Interactive lcoview HTML: `reports/coverage/lcoview/index.html`

Open either report locally with:

```bash
python -m webbrowser reports/coverage/html/index.html
python -m webbrowser reports/coverage/lcoview/index.html
```

The dedicated `lcoview` Docker image contains its Node.js runtime. The project
environment, regular test command, and CI do not require Node or npm.

Direct equivalents:

```bash
uv run alembic upgrade head
uv run pytest
uv run ruff check app tests docs/snippets scripts
uv run mypy --explicit-package-bases app
uv run ty check app
```

OAuth2 route changes should also preserve typed FastAPI request parameters,
keep secrets out of query strings, and update both runtime protocol tests and
OpenAPI contract tests. The detailed rule lives in
[docs/development/architecture/adr-oauth2-typed-fastapi-parameters.md](docs/development/architecture/adr-oauth2-typed-fastapi-parameters.md).

## Build the Documentation

Serve the local documentation site with live reload:

```bash
uv sync --frozen --group docs
uv run --group docs zensical serve
```

Open `http://127.0.0.1:8008`.

For a strict local build that matches CI:

```bash
uv run --group docs pytest --no-cov tests/docs/test_snippets.py
uv run --group docs zensical build --strict
```

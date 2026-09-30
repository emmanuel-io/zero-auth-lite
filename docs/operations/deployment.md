# Deployment

The application in `app/` is the canonical runnable Zero Auth Lite server. It is a
small educational identity provider, not a generic framework or a replacement
for a complete identity platform.

## Deployment Model

Zero Auth Lite targets prototypes, internal applications, and nominal-load
deployments on a single node that do not require high availability.
Native deployment requires a POSIX operating system. Windows hosts must run the
server through WSL or the canonical container deployment.

The node owns application composition and runs outbox delivery, browser-session
cleanup, and OAuth2 cleanup as explicit side processes. SQLAlchemy stores all durable identity,
browser-session, and OAuth2 state.

Multiple application processes on the same node must use the same database,
settings, and signing material. Alembic must run once
before those processes start. Deploying Zero Auth Lite across multiple
application nodes requires coordination and failure-mode testing that the
project does not currently provide or claim to support.

Public identifiers are generated independently as UUIDv4 values. No shared
node allocation or clock coordination is required. `ZA_RUNTIME_DIR` remains
required for the POSIX bootstrap lock used to serialize initial setup.

For a systemd service, let systemd create the runtime directory with the
service user's ownership:

```ini
[Service]
RuntimeDirectory=zero-auth-lite
Environment=ZA_RUNTIME_DIR=/run/zero-auth-lite
```

This directory is ephemeral process state. Do not place it in the persistent
database volume.

Start with one native Uvicorn worker:

```bash
uv run uvicorn app.main:create_app --factory --workers 1 --no-access-log --no-proxy-headers
```

For Gunicorn, install the optional server dependencies and use the maintained
`uvicorn-worker` package:

```bash
uv sync --extra gunicorn
uv run gunicorn --workers 1 \
  --worker-class uvicorn_worker.UvicornWorker \
  --forwarded-allow-ips '' \
  --bind 0.0.0.0:8000 'app.main:create_app()'
```

The canonical Compose stack mounts its dedicated `zero_auth_runtime` volume
where bootstrap coordination needs it. It remains a single-web-worker
configuration.

Do not treat a fixed worker count as a deployment recommendation. SQLite allows
concurrent readers but serializes writes, so additional web workers can improve
independent read throughput while increasing writer contention. Increase the
count only after measuring the deployment's read/write mix and latency. Monitor
`DATABASE_BUSY`/`SQLITE_BUSY` responses, keep transactions short, and reduce
concurrency when the configured busy timeout is regularly exhausted.

## Direct Run

```bash
uv sync --all-groups
cp config/development.example.toml zero-auth-lite.toml
uv run alembic upgrade head
uv run uvicorn app.main:create_app --factory --reload --no-access-log --no-proxy-headers
```

In a second terminal, load the same environment and run durable event delivery:

```bash
uv run python -m app.notifications.worker
```

In two more terminals, load the same environment and run browser-session and
OAuth2 persistence cleanup:

```bash
uv run python -m app.browser_sessions.cleanup_worker
uv run python -m app.oauth2.cleanup_worker
```

Open:

- `http://localhost:8000/health/live`
- `http://localhost:8000/health/ready`
- `http://localhost:8000/api/docs`
- `http://localhost:8000/api/redocs`
- `http://localhost:8000/.well-known/oauth-authorization-server`
- `http://localhost:8000/.well-known/openid-configuration`

This opt-in profile aligns issuer, CORS, CSRF, links, and cookie policy with a
plain-HTTP localhost process. It is deliberately unsuitable for deployment.

## Docker Compose

```bash
docker compose up --build
```

Compose starts:

- a one-shot Alembic migration using the same database volume
- FastAPI on `http://localhost:8000`
- a dedicated notification outbox worker
- a dedicated browser-session cleanup worker
- a dedicated OAuth2 persistence-cleanup worker
- Caddy on `https://auth.zero-auth-lite.localhost:8443`
- Mailpit through Caddy on `https://mailpit.localhost:8443`

Open the canonical HTTPS documentation surfaces at:

- Swagger UI: `https://auth.zero-auth-lite.localhost:8443/api/docs`
- ReDoc: `https://auth.zero-auth-lite.localhost:8443/api/redocs`
- OpenAPI JSON: `https://auth.zero-auth-lite.localhost:8443/api/docs/openapi.json`
- Mailpit: `https://mailpit.localhost:8443`

The backend is also exposed directly on the host loopback interface at
`http://localhost:8000`, but use the canonical HTTPS origin when exercising
browser sessions and secure cookies from Swagger UI. The first browser visit
may require accepting or trusting Caddy's local development certificate.

Compose gives Caddy the fixed internal address `172.30.0.10` and configures the
backend to trust forwarded source addresses only from that exact address. This
keeps the source metadata attached to browser sessions from accepting a forged
`X-Forwarded-For` header from a direct caller. If the Compose subnet or Caddy
address is changed, update `ZA_APP__TRUSTED_PROXY_IPS` to the same exact
`/32`; do not trust the whole container subnet.

The canonical launch commands disable Uvicorn's own proxy-header rewriting.
Zero Auth Lite must receive the direct TCP peer in `request.client` so
`ZA_APP__TRUSTED_PROXY_IPS` remains the single authority that decides whether
`Forwarded` or `X-Forwarded-For` may supply a source address. Apply the same
rule to custom ASGI launchers; do not enable a second proxy trust list there.

Mailpit also keeps its direct `http://localhost:8025` port for local tools and
diagnostics; the HTTPS subdomain is the canonical browser URL.

Compose mounts `config/full-server.example.toml` by default. Select another
host TOML file with `ZA_CONFIG_FILE`:

```bash
ZA_CONFIG_FILE=config/client-credentials.example.toml docker compose up --build
```

## Bootstrap The First Operator

For a direct run, export both variables before first startup against an empty
database:

```bash
export ZA_BOOTSTRAP__OPERATOR_EMAIL=operator@example.com
export ZA_BOOTSTRAP__OPERATOR_PASSWORD='Change-me-1!'
```

Compose mounts the application file selected by `ZA_CONFIG_FILE`; arbitrary
overrides exported by the host shell are not automatically copied into the
backend container. Create an ignored local TOML file, set both bootstrap
values, then select it explicitly:

```bash
cp config/full-server.example.toml zero-auth-lite.toml
# Edit the [bootstrap] table in zero-auth-lite.toml.
ZA_CONFIG_FILE=./zero-auth-lite.toml docker compose up --build
```

The bootstrap creates a new organization and one verified operator only when no users
exist. Organization names are display labels, so bootstrap never selects a preexisting
organization by name. Application workers serialize this check and creation through a
POSIX lock under `ZA_RUNTIME_DIR`; they must therefore share that runtime
directory as described above. Remove the two credentials from the TOML file
after the operator has been created. The backend, outbox worker, and both
cleanup workers receive the selected application configuration; only the
backend acts on bootstrap settings. The migration service receives
`ZA_DB_PATH` alone.

## Database Migrations

Apply the complete migration chain before starting application processes; see
the [migration runbook](migrations.md). Run cleanup and outbox dispatch outside
the web lifespan using the [browser-session cleanup](browser-session-cleanup.md),
[OAuth2 cleanup](oauth2-cleanup.md), and [outbox worker](outbox-worker.md)
runbooks.

A sessionless machine deployment must set `identity_workflow.registration_enabled=false`;
startup rejects public registration without a browser authentication mechanism.
This profile has no human principal capable of using the operator
client-administration API. Create its confidential clients with the local
[machine-client provisioning command](oauth2-client-provisioning.md). Machine
tokens remain unable to acquire operator roles.

## Supported Server Surface

- Browser-session mechanics: login, logout, session listing, session
  revocation, scoped logout, and CSRF token exposure.
- Email authentication workflows: email verification, password reset, and
  organization invitations through local SMTP-compatible delivery.
- Identity administration: organization-admin user management under
  `/api/v1/organization/users` and current organization metadata under `/api/v1/organization`.
- OAuth2 and OIDC: authorization code with PKCE, refresh tokens, client
  credentials, device code, revocation, introspection, discovery, JWKS, ID
  tokens, and UserInfo.
- Authorization: explicit roles, permissions, organization boundaries, OAuth2 scopes,
  and bearer principal resolution.

## Intentional Omissions

The local stack is not a deployment template. A commercial service still needs
external secret management, migrations, backup/restore, automated signing-key
rotation or an explicit operational procedure for the supported manual
rotation, monitoring, alerting, and any bot detection, fraud detection, WAF, or
edge-security controls required by its threat model. Request limiting must be
added at a trusted deployment boundary when the server is exposed to untrusted
traffic; see [security](security.md#request-limiting-and-edge-security).

High-availability multi-node deployment is intentionally outside the supported
scope.

SQLite is the only supported relational database for this server. SQLAlchemy
keeps persistence explicit and composable; its use does not imply compatibility
with other database engines.

Zero Auth Lite deliberately excludes SAML, SCIM, LDAP, social login, provider
federation, enterprise IAM administration, bot or fraud detection, built-in
request limiting, WAF or edge-security systems, and Kubernetes deployment
scaffolding.

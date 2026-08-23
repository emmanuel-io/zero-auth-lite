# Installation

Zero Auth Lite is a FastAPI reference identity provider. The canonical runnable
application lives under `app/`.

## Run The Server

Complete the [initial configuration](configuration.md) before starting an empty
server so that Zero Auth Lite can bootstrap its first operator.

```bash
uv sync --all-groups --all-extras
cp config/development.example.toml zero-auth-lite.toml
uv run alembic upgrade head
uv run uvicorn app.main:create_app --factory --reload
```

In another terminal from the same directory, start durable notification delivery:

```bash
uv run python -m app.events.worker
```

In a third terminal from the same directory, start OAuth2 persistence cleanup:

```bash
uv run python -m app.oauth2.cleanup_worker
```

Run exactly one continuous cleanup worker for the database. See
[OAuth2 cleanup](../operations/oauth2-cleanup.md) for one-shot scheduler and
deployment options.

Open Swagger UI at `http://localhost:8000/api/docs` or ReDoc at
`http://localhost:8000/api/redocs` to inspect the API.
The built-in browser UI is enabled by default. Opening a valid authorization
URL leads through `/login` and, when the client requires it, `/consent` before
returning to the registered callback.
The direct-run profile is intentionally HTTP-only and must not be used for a
deployed server. Compose keeps the local HTTPS cookie and issuer topology.

The server expects a migrated SQLAlchemy schema. Run the Alembic command again
after pulling a change that adds migrations.

## Database Migrations

Prepare the canonical database with:

```bash
uv run alembic upgrade head
```

## Local Compose Stack

For a first Compose run, create the ignored TOML file described in the
[initial configuration](configuration.md), then start the stack:

```bash
cp config/full-server.example.toml zero-auth-lite.toml
ZA_CONFIG_FILE=zero-auth-lite.toml docker compose up --build
```

This first runs an Alembic migration container, then starts FastAPI, the outbox
worker, the OAuth2 cleanup worker, Caddy, and Mailpit. Use Mailpit at
`https://mail.zero-auth-lite.localhost:8443` to inspect verification and
password-reset messages.
The backend starts only after the migration has completed successfully.

For the Compose HTTPS topology, open:

- Swagger UI: `https://auth.zero-auth-lite.localhost:8443/api/docs`
- ReDoc: `https://auth.zero-auth-lite.localhost:8443/api/redocs`
- OpenAPI JSON: `https://auth.zero-auth-lite.localhost:8443/api/docs/openapi.json`
- Mailpit: `https://mail.zero-auth-lite.localhost:8443`

Prefer the HTTPS URLs for interactive browser-session calls because the local
profile uses secure cookies. Caddy uses a local development certificate, so a
browser may ask you to trust or accept it on the first visit.
Mailpit remains available directly at `http://localhost:8025` for local tooling.

Continue with [your first OAuth2 client](first-client.md). For deployment and
persistence details, see [Deployment](../operations/deployment.md) and
[Database](../operations/database.md).

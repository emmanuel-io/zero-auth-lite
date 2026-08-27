# Development Setup

Zero Auth Lite requires Python 3.12 or newer and uses `uv` to manage its development
environment.

```bash
uv sync --all-groups --all-extras
```

Run the project checks through the maintained wrapper:

```bash
./scripts/check.sh test
./scripts/check.sh coverage
./scripts/check.sh ruff
./scripts/check.sh mypy
./scripts/check.sh ty
./scripts/check.sh format
```

Tests should verify observable authentication and authorization behavior rather
than implementation details. Before changing a feature boundary, read the
[repository structure](repository-structure.md), the relevant architecture
decisions, and the matching project skill under `.agents/skills/`.

## Local Debugging

For day-to-day development, run FastAPI and its workers directly from the
console. This keeps reloads, breakpoints, tracebacks, and database inspection
close to the code being changed. Mailpit can remain isolated in a container:

```bash
docker run -d \
  --name mailpit \
  -p 127.0.0.1:1025:1025 \
  -p 127.0.0.1:8025:8025 \
  axllent/mailpit
```

Create the ignored development configuration from its versioned example. It
already points SMTP delivery at `localhost:1025`:

```bash
cp config/development.example.toml zero-auth-lite.toml
```

Every Zero Auth Lite process started from the project directory reads this file.
The development profile sets `app.log_level = "DEBUG"`. Zero Auth Lite writes
application logs to the process console (`stdout`); it does not send logs to
syslog itself. A process supervisor or container runtime may capture and
forward that console stream independently.

Run the migration and application in one terminal:

```bash
uv run alembic upgrade head
uv run uvicorn app.main:create_app --factory --reload
```

Run both commands from the repository root so `zero-auth-lite.toml` is loaded,
then use `http://localhost:8000` as the browser origin. If the server starts
without this direct-run profile, the HTTPS cookie defaults prevent login over
plain HTTP. The profile also trusts `http://127.0.0.1:8000` for direct debugging;
do not switch hostnames between loading and submitting one form.

Run durable notification delivery in another terminal so verification,
invitation, and password-reset messages reach Mailpit:

```bash
uv run python -m app.events.worker
```

Run OAuth2 persistence cleanup in a third terminal so expired protocol state
is removed outside the FastAPI process:

```bash
uv run python -m app.oauth2.cleanup_worker
```

Run exactly one continuous cleanup worker for the development database. The
[OAuth2 cleanup runbook](../operations/oauth2-cleanup.md) also documents
one-shot execution for scheduled deployments.

Open the built-in authentication UI at `http://localhost:8000/login` and
Mailpit at `http://localhost:8025`. Stop the Mailpit container with
`docker stop mailpit`; a stopped container can be reused with
`docker start mailpit`.

Use the full Compose stack when checking the complete local topology rather
than debugging one Python process. It exercises Caddy, HTTPS, secure cookies,
the canonical `auth.zero-auth-lite.localhost` origin, migrations, workers, and
Mailpit together:

```bash
docker compose up --build
```

This command intentionally uses Compose's default HTTPS profile. Do not pass
the direct HTTP `zero-auth-lite.toml` created above to Compose; its issuer,
cookie, and CSRF settings describe a different browser origin.

The two workflows serve different purposes: direct console processes are the
recommended development loop, while Compose is the integration check for
proxy, origin, cookie, and multi-process behavior. Do not open the direct HTTP
server with the Compose HTTPS origin, or the Compose server with the direct
HTTP origin; their cookie and CSRF settings intentionally differ.

## Documentation

Serve the documentation site with live reload:

```bash
uv sync --frozen --group docs
uv run --group docs zensical serve
```

Run the strict documentation checks before contributing a documentation
change:

```bash
uv run --group docs pytest --no-cov tests/docs/test_snippets.py
uv run --group docs zensical build --strict
```

Use the [documentation and contribution checklist](documentation.md) when a
change affects the public contract or the canonical server documentation.

# Initial Configuration

Zero Auth Lite loads the optional `zero-auth-lite.toml` file from its working directory
and then applies `ZA_*` environment overrides. Set `ZA_CONFIG_FILE` to select a
different file; an explicitly selected file must exist. The committed examples
provide coherent issuer, CORS, CSRF, cookie, and database defaults for local
use. The `config/` catalog contains three supported profiles:

- `full-server.example.toml` enables the complete server and is the Compose
  default;
- `development.example.toml` adapts that complete server to direct local HTTP;
- `client-credentials.example.toml` enables only the Client Credentials OAuth2
  grant and disables browser sessions. The canonical identity workflow APIs
  remain mounted under `/api/v1/auth` when authentication uses an external UI.

The full-server and development profiles list every setting. Commented values
show the application defaults; active values define the topology or mark
secrets that must be replaced. See the
[settings reference](../reference/settings.md) for detailed precedence,
constraints, and security requirements.

## Bootstrap The First Operator

For a direct run, export both variables before the first application startup
against an empty database:

```bash
export ZA_BOOTSTRAP__OPERATOR_EMAIL=operator@example.com
export ZA_BOOTSTRAP__OPERATOR_PASSWORD='Change-me-1!'
```

For Compose, copy the example TOML file and set both values in its `[bootstrap]`
table:

```bash
cp config/full-server.example.toml zero-auth-lite.toml
# Edit zero-auth-lite.toml and set operator_email and operator_password.
ZA_CONFIG_FILE=zero-auth-lite.toml docker compose up --build
```

Host-shell overrides are not automatically passed into the Compose backend.
The bootstrap creates a new organization and one verified operator only when no
users exist. Remove both credentials from the TOML file after the operator has
been created.

## Persistence

SQLAlchemy stores all durable authentication state. The direct-run profile can
use a local SQLite database explicitly:

```bash
export ZA_DB_PATH=./data/zero-auth-lite.db
```

`ZA_DB_PATH` is a filesystem path, not a SQLAlchemy URL. Zero Auth Lite is
intentionally SQLite-only and constructs the asynchronous SQLite URL itself.

Run `uv run alembic upgrade head` before starting a direct server. Compose runs
the migration service automatically. Continue with the
[installation](installation.md) or register [your first client](first-client.md).

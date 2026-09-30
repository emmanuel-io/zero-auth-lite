# Database Migrations

The runnable server always expects a migrated relational schema. It does not
create tables implicitly at startup.

Apply the current Alembic head before starting application processes:

```bash
uv run alembic upgrade head
```

Alembic reads only `ZA_DB_PATH`, `ZA_DB_ECHO`, and the matching root values from
the selected TOML file. It deliberately does not validate unrelated server,
OAuth2, mail, or UI settings: schema management must remain available while
those parts of a deployment are being configured or repaired.

Deployments must target `head`, not a concrete revision identifier. This keeps
the command valid when later schema changes add migrations. The Compose stack
enforces this ordering with its one-shot `migrate` service; direct runs and
other deployment systems must invoke Alembic explicitly.

The initial revision is an implementation detail. Deployment automation must not
hard-code that revision identifier; it must continue to target `head`.

The outbox, browser-session cleanup, and OAuth2 cleanup workers also require the
current schema and fail instead of operating against an unknown migration
state. Contributors who change ORM models should follow the separate
[migration development guide](../development/database-migrations.md).

## Pre-release Databases

Zero Auth Lite has not published a stable database schema. Its tracked migration
history starts with one canonical baseline and applies later reviewed revisions in
order. A database whose current Alembic revision belongs to that history is an
upgrade target and should be advanced with `uv run alembic upgrade head`.

Development databases created from schemas that are not represented in the tracked
migration history are not upgrade targets. Recreate those databases and apply
`uv run alembic upgrade head`.

Do not use this pre-release policy once a schema revision has shipped in a
release. From that point onward, preserve released revisions and add forward
migrations for every schema change.

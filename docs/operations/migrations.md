# Database Migrations

The runnable server always expects a migrated relational schema. It does not
create tables implicitly at startup.

Apply the complete Alembic chain before starting application processes:

```bash
uv run alembic upgrade head
```

Applying through `head` creates the current canonical server schema. In this
checkout, `head` is the single canonical initial revision. Deployments must not
hard-code that revision identifier: targeting `head` keeps the command correct
when later migrations extend the chain. The Compose stack enforces this
ordering with its one-shot `migrate` service; direct runs and other deployment
systems must invoke Alembic explicitly.

The outbox and OAuth2 cleanup workers also require the current schema and fail
instead of operating against an unknown migration state. Contributors who
change ORM models should follow the separate
[migration development guide](../development/database-migrations.md).

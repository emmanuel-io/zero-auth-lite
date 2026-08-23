# Database Migration Development

Alembic migrations are the explicit history of the canonical server schema.
The application does not create or modify tables at startup, so every ORM
schema change must have a reviewed migration before it can be used.

The current checkout starts from one canonical initial migration. Development
databases created from an earlier schema are disposable and must be recreated;
there is intentionally no data-upgrade path for unpublished schemas.

## Generate a Migration

First, change the SQLAlchemy models. If a new model owns a table, also import
it from `app/db/alembic.py` so Alembic includes it in the canonical metadata.

Autogeneration compares that metadata with a migrated database. Create an
isolated database and bring it to the current migration head before generating
the revision:

```bash
migration_dir="$(mktemp -d)"
export ZA_DB_PATH="$migration_dir/zero-auth-lite.db"
uv run alembic upgrade head
uv run alembic revision --autogenerate \
  --rev-id 20260817_0002 \
  -m "describe the schema change"
```

Replace the example revision identifier with the next identifier in the
`YYYYMMDD_NNNN` sequence used by `alembic/versions/`. Keep the generated file
in that directory and confirm that its `down_revision` points to the current
head.

Do not run autogeneration against an empty or outdated database. Alembic would
then describe existing schema history as if it were part of the new change.

## Review the Generated Revision

Autogeneration is a starting point, not a complete migration. Read both
`upgrade()` and `downgrade()` before committing the file. In particular,
verify that:

- every operation belongs to the intended ORM change;
- table, index, foreign-key, unique, and check-constraint names follow the
  naming convention in `app/db/base.py`;
- constraint names are not prefixed twice by that naming convention;
- SQLite table alterations use `op.batch_alter_table()` when required;
- renamed tables or columns are expressed as renames rather than destructive
  drop-and-create operations;
- required data transformations happen before adding stricter constraints;
- existing user, organization, session, and token data remain valid;
- `downgrade()` provides a deliberate reverse operation, including any limits
  on recovering transformed or deleted data.

Add explicit type annotations and Google-style docstrings to the generated
revision so it follows the surrounding migration files.

## Validate the Migration

Run the migration tests after reviewing the revision:

```bash
uv run pytest tests/app/db/test_migrations.py
```

Update the canonical-head assertion in that test for the new revision. Add a
focused migration test when the change renames data, transforms existing rows,
or enforces a new invariant. Such a test should exercise the relevant upgrade
and downgrade path and verify the persisted values, not only the column list.

The migration suite builds a database through the complete revision chain and
runs Alembic's schema-drift check against the ORM metadata. Finish by running
the complete project checks:

```bash
./scripts/check.sh test
./scripts/check.sh ruff
./scripts/check.sh mypy
./scripts/check.sh ty
```

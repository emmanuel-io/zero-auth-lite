# Database

The application owns the SQLite engine and request-scoped SQLAlchemy session
lifecycle in `app/db/`. Concrete ORM rows are grouped in `app/db/models/` by
the authentication concept they persist: users, organizations, browser
sessions, OAuth2 clients and grants, workflow tokens, and notification events.
Feature services own the queries and lifecycle decisions that operate on those
rows.

SQLite through SQLAlchemy is the only supported durable backend:

```bash
export ZA_DB_PATH=./data/zero-auth-lite.db
```

This value is a filesystem path rather than a SQLAlchemy URL. Zero Auth Lite builds
the `sqlite+aiosqlite` URL internally. Set `ZA_DB_ECHO=true` only for
local SQL debugging; statements may expose operational data in logs. No store
or database-engine selector exists. SQLAlchemy keeps persistence readable; it
is not a compatibility promise for other database engines.

Prepare the relational schema before starting the server by following the
[migration runbook](migrations.md). Contributors changing the ORM schema should
instead use the [database migration development guide](../development/database-migrations.md).

The canonical server applies a small set of SQLite pragmas on every connection.
The busy timeout is installed before operations such as WAL negotiation that
may need to wait for another connection:

- `PRAGMA busy_timeout=5000`
- `PRAGMA journal_mode=WAL`
- `PRAGMA synchronous=NORMAL`
- `PRAGMA foreign_keys=ON`

Zero Auth Lite also disables sqlite3's legacy implicit transaction behavior and
emits `BEGIN` explicitly. Read-first operations and nested savepoints therefore
remain inside the same transaction boundary as their later writes.

These settings keep local development more reliable by allowing concurrent
reads during writes, enforcing foreign keys, and reducing short lock failures
when multiple requests touch the same SQLite database.

Feature dependencies use SQLAlchemy for all durable authentication state.
Browser sessions, OAuth2 sessions, token pairs, and refresh-token history share
request-scoped SQLAlchemy transactions where their lifecycle requires it.
An OAuth2 session owns immutable client, grant, scope, and principal metadata.
Its token-pair row owns only the currently usable token hashes, identifiers,
and expiry deadlines.

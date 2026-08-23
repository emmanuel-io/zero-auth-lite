---
name: sqlite
description: Work on Zero Auth Lite persistence, SQLAlchemy models and queries, Alembic migrations, transactions, concurrency, database configuration, or SQLite performance and stability. Use for any change or review involving app/db, relational storage, indexes, constraints, WAL, locking, cleanup, or database operations.
---

# SQLite

## Scope

Treat SQLite as the only supported database for Zero Auth Lite. Use SQLAlchemy to
keep persistence readable and composable, not to promise portability to other
database engines.

Do not introduce compatibility layers, abstractions, constraints, locking
strategies, migration branches, or review findings solely for PostgreSQL or
cross-database support.

Keep database behavior suitable for one application node. Multiple processes
on that node may share the same SQLite database and runtime directory, but
multi-node operation is outside the supported deployment model.

## Canonical Connection Behavior

Keep SQLite connection setup centralized in `app/db/engine.py`. Preserve these
settings unless a measured problem and its durability tradeoff are documented:

- set `PRAGMA busy_timeout=5000` before operations that may need a lock;
- use `PRAGMA journal_mode=WAL` so readers can continue during a write;
- use `PRAGMA synchronous=NORMAL` for the current durability/performance
  balance;
- enable `PRAGMA foreign_keys=ON` on every connection;
- disable sqlite3 legacy transaction handling and emit explicit `BEGIN` for
  every SQLAlchemy transaction, including read-first flows.

Remember that `foreign_keys` and `busy_timeout` are connection-local. WAL mode
persists on the database file, but each process must still apply the canonical
connection configuration.

Do not add pragmas such as `mmap_size`, `cache_size`, `temp_store`, or a custom
WAL checkpoint policy without a workload measurement and an explanation of
memory, durability, and operational effects.

## Transactions And Concurrency

Reason from SQLite's single-writer model:

- keep write transactions short;
- do not perform mail delivery, network I/O, or expensive password hashing
  while holding a write transaction;
- use database uniqueness constraints and conditional `UPDATE` or `DELETE`
  statements for collision and single-use guarantees;
- remember that `SELECT ... FOR UPDATE` does not provide row locks in SQLite;
- do not propose `SKIP LOCKED`, advisory locks, or PostgreSQL isolation
  behavior;
- treat `busy_timeout` as relief for short contention, not as a correctness
  mechanism;
- retry `SQLITE_BUSY` only with a bounded policy when the whole operation is
  safe to repeat.

Increasing the number of application or worker processes can improve read
concurrency but cannot create parallel SQLite writers. Consider write volume
and transaction duration before recommending more processes.

Keep transaction ownership explicit. Request-scoped dependencies may commit
successful requests and roll back failures; services should normally flush so
several mutations remain composable. Commit inside a service only when an
autonomous workflow or a protocol rule clearly requires it.

## Schema And Queries

- Use SQLite-compatible column types, constraints, defaults, and indexes.
- Use Alembic batch operations for table changes that SQLite cannot perform
  directly.
- Preserve database constraints for security and lifecycle invariants; do not
  rely only on application checks.
- Declare every ORM relationship with `lazy="raise"`. Never rely on attribute
  access to issue an implicit query; load required relationships deliberately
  with an explicit query or loader option at the service boundary.
- Select eager-loading strategies per use case. Do not apply broad joined or
  select-in loading merely to silence a raised unloaded-relationship error.
- Remember that SQLite does not automatically index foreign-key columns.
- Match composite-index order to real filtering and ordering paths.
- Avoid redundant indexes already covered by a primary key or another index.
- Prefer bounded, deterministic cleanup batches over large delete
  transactions.
- Add pagination to lists that can grow without a small domain bound.

Before adding an index or rewriting a query for performance, inspect the real
query path and use SQLite's `EXPLAIN QUERY PLAN` when execution is authorized.
Account for write amplification and migration cost when adding indexes.

## Stability And Operations

- Store the database on persistent local storage with reliable POSIX locking;
  do not place it on an ephemeral or casually shared network filesystem.
- Ensure every application process, migration, outbox worker, and cleanup
  worker points to the same database file.
- Run Alembic once before application processes start.
- Monitor lock errors, write-transaction duration, database size, WAL size,
  checkpoint behavior, and cleanup backlog before tuning.
- Keep maintenance jobs incremental so they do not monopolize the writer.

Backup and restore are not implemented yet. When they are added, use a
SQLite-aware online backup mechanism or a documented shutdown procedure.
Never document copying only the main database file while an active WAL may
contain committed data.

## Review Checklist

When reviewing database work:

1. Confirm that the design assumes SQLite only.
2. Identify the transaction owner and the duration of every write path.
3. Check constraints and conditional mutations for race-sensitive invariants.
4. Check query bounds, ordering, indexes, and cleanup batch sizes.
5. Check that relationships reject lazy loading and that required related data
   is loaded explicitly by the owning query.
6. Check migration compatibility with SQLite table-alteration limits.
7. State performance suggestions as measurements to validate, not generic
   database folklore.
8. Keep backup implementation out of scope until it is requested explicitly.

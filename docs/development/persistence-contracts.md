# Direct SQLAlchemy Persistence

The canonical server supports SQLite through SQLAlchemy. Relational services
receive the request-scoped `AsyncSession` directly and keep each query beside
the authentication or authorization decision it supports. There is no
repository or store compatibility layer for alternate relational backends.

Canonical ORM models live together in `app/db/models/`, which makes the
complete relational schema easy to inspect. Feature folders own the services,
DTOs, criteria, and ORM-to-DTO mappings that interpret those rows. HTTP schemas
remain beside the versioned API routes.

## Relationship Loading

ORM relationships declare `lazy="raise"`. Accessing an unloaded relationship
must fail instead of issuing an implicit query. This keeps database I/O visible,
avoids accidental N+1 queries, and prevents serialization or property access
from silently extending a transaction.

Services load related data deliberately in the query that needs it, using an
explicit join, a separate bounded query, or a targeted SQLAlchemy loader
option. Do not enable default lazy loading or broad eager loading to hide a
missing query decision.

## Transaction Policy

The database dependency commits pending work after a successful request and
rolls back an exception. Internal service mutations flush so callers can
compose several changes atomically. Explicitly named autonomous operations own
their transaction when they cannot remain request-composed. Protocol mutations
that must survive an error, such as refresh-token family revocation or device
polling backoff, commit deliberately before raising the protocol error.

Single-use artifacts are consumed with conditional `UPDATE` or `DELETE`
statements. SQLite uniqueness constraints and the configured explicit
transaction start protect collision and administrator invariants. External
capabilities—password hashing, event publication, and mail delivery—remain
protocol-based dependencies because they are genuine integration boundaries.

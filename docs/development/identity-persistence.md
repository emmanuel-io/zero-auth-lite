# Identity Persistence

Users and organizations are application-owned SQLAlchemy models. Services query them
through the same request-scoped `AsyncSession` used for sessions, OAuth2 state,
identity workflow tokens, and the outbox. This makes security-sensitive lifecycle
changes visibly atomic without an identity repository abstraction.

`app.identity.mapping` contains only ORM-to-DTO conversion helpers. Services
continue to expose identity DTOs rather than leaking ORM rows to HTTP handlers.
Email normalization, availability, and lifecycle transitions remain focused
shared helpers because every registration and lifecycle path must apply
identical rules. `UserEmailDB` is the source of truth: services explicitly load
the current and, when needed, pending address before projecting the stable HTTP
fields `email`, `pending_email`, and `email_verified`.

Normalized-address lookups use `active_email_predicate()` to match the existing
active-address partial index. Its status values are fixed SQL literals because
SQLite cannot match parameterized status lists to that index. Login and mail
requests also require the current status, so pending addresses stay reserved
without becoming login or recovery identifiers.

The request dependency commits on a successful response and rolls back when an
exception crosses the boundary. Services normally flush internal mutations.
An operation that must end the request transaction before expensive work uses
an explicitly named autonomous method, such as
`change_password_autonomously()`. It first rolls back request-scoped state,
including automatic browser-session activity, then owns its short independent
write transaction.

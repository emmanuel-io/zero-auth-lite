# Identity Persistence

Users and organizations are application-owned SQLAlchemy models. Services query them
through the same request-scoped `AsyncSession` used for sessions, OAuth2 state,
auth workflow tokens, and the outbox. This makes security-sensitive lifecycle
changes visibly atomic without an identity repository abstraction.

`app.identity.mapping` contains only ORM-to-DTO conversion helpers. Services
continue to expose identity DTOs rather than leaking ORM rows to HTTP handlers.
Email normalization, availability, and lifecycle transitions remain focused
shared helpers because every registration and lifecycle path must apply
identical rules. `UserEmailDB` is the source of truth: services explicitly load
the current and, when needed, pending address before projecting the stable HTTP
fields `email`, `pending_email`, and `email_verified`.

The request dependency commits on a successful response and rolls back when an
exception crosses the boundary. Services normally flush internal mutations.
An operation that must release the request transaction before expensive work
uses an explicitly named autonomous method, such as
`change_password_autonomously()`, which then owns its short write transaction.

# Transaction Boundaries And Durable Outbox

## Status

Accepted.

## Context

Identity commands commonly update several related rows: a user, its sessions,
OAuth2 state, and sometimes a notification. Committing inside each low-level
operation makes those use cases only partially atomic. Sending mail inside the
transaction has the opposite problem: SMTP cannot roll back.

Browser sessions and OAuth2 state are relational. Security-sensitive user
changes can therefore revoke both forms of session authority in the same SQL
transaction. This includes credential and eligibility changes as well as role
or organization changes that alter authorization.

## Decision

Every operation belongs to one of four explicit categories:

1. A **read** never accepts a `commit` argument.
2. A **request-composed command** flushes its writes and leaves transaction
   ownership with the request dependency. This allows identity, session, and
   outbox changes to compose atomically; not every command exposes a `commit`
   argument.
3. A **persistent security mutation** commits before deliberately returning a
   protocol error. Refresh-token reuse/expiry revocation and device polling
   throttling are examples. Each such commit is documented at the call site.
4. An **expensive credential mutation** may release a completed read
   transaction before password hashing, then use a dedicated short write with
   a conditional update. Such a method is named ``*_autonomously`` and cannot
   be composed atomically with unrelated request-scoped writes. Password
   change uses this category so Argon2 work never holds a SQLite transaction.

Private mutation helpers and relational services call `flush()` only. The public
service method owns the commit decision. Logs emitted before that commit use
`outcome=attempted`: they describe a prepared operational attempt, not a
committed result. No external business side effect is executed before commit.

## Durable Outbox

`EventPublisher.publish(event)` means “persist this delivery intention in the
current transaction.” It does not invoke a handler. The publisher writes one
row to `auth_event_outbox` using the mutation's SQLAlchemy session, so the
business change and delivery intention either commit or roll back together.

The allowlist contains account verification, password reset, email change, and
invitation notifications. Session revocations remain ordinary SQL writes in
their business transaction.

The dedicated dispatcher processes at most one configured batch per poll, but
claims each row only when it is ready to process it. This keeps a queued row's
lease from expiring behind slow SMTP calls. A lightweight heartbeat renews the
lease while external delivery remains in flight. A conditional update prevents
two workers from owning the same row. Failed deliveries retain their error and
use capped exponential retry; expired leases are reclaimable after a crash.
Delivered rows are retained temporarily and purged periodically.

Delivery is **at least once**. A crash after SMTP accepts a message but before
`processed_at` commits can send a duplicate. Exactly-once SMTP delivery would
require cooperation the protocol does not provide.

Disabled email, deleted target accounts, and email rows that no longer have
the state required by their workflow complete the event without
revealing account existence. The dispatcher records whether the event was
delivered, discarded because email was disabled, or discarded because its
target no longer exists. Email-disabled events do not create or invalidate
workflow tokens.

## Idempotent Workflow Tokens

The outbox payload never contains a raw token. During the first delivery, the
dispatcher derives the raw token using HMAC over the event id, email-row id,
and purpose. The token stores the active `derivation_key_id`; its secret is read
from the active key or the explicitly retained previous-key map. Only the token
hash, expiration, key identifier, and unique `source_event_id` are stored.

A retry of the same event reconstructs the same link while that request remains
the newest unused request. If an SMTP outage outlives the token TTL, the same
derived token receives a new validity window before the next attempt. Each
token stores the source event's business timestamp.
A delayed older event is completed without sending once a newer request exists;
it cannot invalidate or replace the newer token. A distinct newer request
invalidates the previous active token for that purpose. Token lifetime starts
at the first effective processing attempt, not when the HTTP request enqueues
the event.

Key rotation does not rewrite active token hashes. Retries resolve the key by
the identifier persisted with the token and verify the reconstructed hash before
building an email. Old secrets must remain configured until their tokens are no
longer needed. If a retained key is missing or wrong, delivery remains pending
rather than sending an unusable link.

## SQL Session Authority

SQL remains authoritative for user activation, browser-session invalidation,
OAuth2 sessions, token pairs, and consumed refresh-token history. A security
change records `user.sessions_invalid_before`, ends OAuth2 sessions, deletes
their token pairs, and revokes browser-session rows in the same transaction.
Browser-session resolution also rejects sessions older than the invalidation
timestamp as defense in depth. No external cleanup event or cross-store
compensation is required.

Token issuance, rotation, token-family expiry, and refresh-token history share
one SQL transaction. A failed commit can therefore be rolled back as one unit.

## Consequences

Commands remain composable without committing early. HTTP adapters let the
request-scoped database dependency commit successful responses. Autonomous
entry points, such as the local OAuth2 machine-client provisioning CLI, open
and own an explicit transaction around service persistence.
A service commits internally only when protocol state, such as device polling
backoff, must survive the error response returned to the client. Notification
responses now mean “scheduled,” not necessarily “sent.” Operations must monitor
outbox age, retries, and failures.
The design adds one explicit side process but no broker or general-purpose
worker platform. The web lifespan never starts the dispatcher. Compose runs one
worker by default, while direct and managed deployments must start it
separately.

This is a deliberate single-node design. Outbox leases make local processing
recoverable and prevent concurrent ownership of one row. They also make
multiple explicitly configured dispatcher processes safe, but they are not a
claim of high-availability multi-node operation, automated failover, or a
distributed worker platform.

## Rejected Alternatives

Committing inside every low-level operation was rejected because it prevents atomic use-case
composition. A fully implicit unit-of-work abstraction was rejected because it
hides the boundary this educational server intends to make visible. Inline
notification delivery was rejected because SMTP cannot share the SQL
transaction.

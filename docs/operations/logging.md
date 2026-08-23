# Logging And Monitoring

Record authentication outcomes, client IDs, public subject identifiers, source
context, and revocation events without recording secrets or tokens. Never log
raw access or refresh tokens, client secrets, notification links, or outbox
payload secrets.

Alert on refresh-token reuse, repeated client-authentication failures,
signing-key problems, deployment-limiter failures, and outbox delivery backlog.
Monitor pending outbox age, retry counts, lease recovery, and accumulated
delivery errors, and size retention and cleanup for the expected notification
volume.

Give security logs an explicit retention and access policy. Zero Auth Lite does not
ship a complex observability stack; collection, storage, alert routing, and
access controls belong to the deployment boundary.

Essential security events use stable `event`, `outcome`, and `reason` fields.
They cover browser login outcomes, browser and security-session revocation,
OAuth2 client provisioning and credential changes, token issuance and
revocation, and refresh-token rotation or reuse. Subjects and organizations
use public `usr_...` and `org_...` identifiers; OAuth2 sessions use `oas_...`.
Failed login attempts use a keyed email hash instead of the submitted address.
For request-scoped mutations, `outcome=attempted` means that the mutation was
prepared and flushed in the request transaction; the request dependency still
owns the commit, so that event does not claim commit success. Operations that
finish an independent transaction before logging may use `outcome=success`.

Zero Auth Lite writes application logs to `stdout`. Each completed HTTP request has
one summary containing its method, path, status, duration, and correlation ID.
The query string is intentionally omitted because OAuth2 codes and
authentication workflow tokens may appear there. The same correlation ID is
returned as `X-Request-ID` and is reused when a valid client-supplied request ID
is accepted.

Logs emitted outside an HTTP request, including startup, cleanup, and outbox
worker activity, use `cid:background` because no request correlation exists.
When a request publishes a durable outbox event, its correlation ID is stored
with that event. The delivery worker restores it while building, sending,
retrying, and recording the result, so those later logs remain connected to
the initiating request. Events created outside request handling and legacy
rows without this metadata continue to use `cid:background`.
Accepted UUID request IDs are normalized to the RFC 9562 hexadecimal
representation: 16 bytes encoded as 32 lowercase hexadecimal characters
without hyphens. The outbox column uses that same explicit length rather than
an unrelated storage allowance. This representation is also compatible in
size with a W3C Trace ID, but Zero Auth Lite does not claim OpenTelemetry tracing
semantics.
Application `DEBUG` logging keeps the low-level `aiosqlite` driver and general
SQLAlchemy internals at `WARNING`, while `sqlalchemy.engine` remains at `INFO`.
This shows SQL statements, bound parameters, and transaction boundaries without
logging each cursor callback. At application level `INFO` or above, SQL query
logging is disabled. The database echo setting remains available for focused
diagnostics outside this default profile.

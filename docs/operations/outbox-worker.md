# Run The Outbox Worker

Notification intentions are committed to the SQL outbox with the identity
change that created them. The FastAPI process only persists those intentions.
A dedicated worker delivers them after commit:

```bash
uv run python -m app.notifications.worker
```

Run this command as a long-lived side process with the same application
settings and database as the web server. It validates that Alembic migrations
are current before polling. When mail is enabled, the worker constructs one
mail service, template environment, and TLS context for its complete lifetime.
It does not apply deployment-owned request controls.

Compose starts one `outbox-worker` service automatically.
For a direct run, start the command in a second terminal after loading the same
environment. For a managed deployment, define it as a separate service beside
the web process. Stopping or scaling web workers then has no effect on outbox
concurrency.

One worker is enough for the supported topology. Row claims and renewable
leases prevent concurrent ownership, so an operator may explicitly run more
than one, but Zero Auth Lite does not provide distributed orchestration or automatic
failover.

If the worker is stopped, committed events remain durable and are retried when
it returns; email delivery is delayed. Delivery is at least
once, so an SMTP message can be duplicated if the process crashes after the
mail server accepts it but before SQL records completion. Monitor pending event
age, retry counts, and failures. Transient delivery failures are retried with
capped exponential backoff. Invalid persisted payloads and mail template errors
are recorded as permanent failures instead of being retried indefinitely. A
registered event without a notification builder is also terminal and signals a
code or deployment mismatch.
Configuration failures while constructing the mail service stop worker startup
so operators can correct them.

Processed events remain for `notification_outbox.retention_seconds`. At each
cleanup interval, the worker drains events past a fixed retention cutoff in
transactions of at most `cleanup_batch_size` rows. Each batch commits before
the next begins, releasing SQLite's writer between batches. Shutdown is checked
between batches; a backlog is not limited to one batch per interval.

The same worker also cleans up workflow tokens after they have been consumed
or expired for at least `retention_seconds`, using the same cleanup interval
and batch size. Tokens for an email with any pending notification are retained,
including claimed or retrying notifications. Those records let retries recover
the same token and prevent older queued requests from replacing newer tokens.
Keep the outbox worker running to perform both retention tasks.

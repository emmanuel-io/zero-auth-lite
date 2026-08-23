# Run The Outbox Worker

Notification intentions are committed to the SQL outbox with the identity
change that created them. The FastAPI process only persists those intentions.
A dedicated worker delivers them after commit:

```bash
uv run python -m app.events.worker
```

Run this command as a long-lived side process with the same application
settings and database as the web server. It validates that Alembic migrations
are current before polling and reserves a Snowflake node because notification
delivery may create workflow tokens. Processes on one host coordinate through
`ZA_RUNTIME_DIR`; separate containers must use distinct explicit
`ZA_SNOWFLAKE_NODE_ID` values or a shared POSIX lock directory. The
worker does not apply deployment-owned request controls.

Compose starts one `outbox-worker` service automatically and assigns Snowflake
node `0` to the backend and node `1` to the outbox worker. For a direct run,
start the command in a second terminal after loading the same environment. For
a managed deployment, define it as a separate service beside the web process.
Stopping or scaling web workers then has no effect on outbox concurrency.

One worker is enough for the supported topology. Row claims and renewable
leases prevent concurrent ownership, so an operator may explicitly run more
than one, but Zero Auth Lite does not provide distributed orchestration or automatic
failover.

If the worker is stopped, committed events remain durable and are retried when
it returns; email delivery is delayed. Delivery is at least
once, so an SMTP message can be duplicated if the process crashes after the
mail server accepts it but before SQL records completion. Monitor pending event
age, retry counts, and failures.

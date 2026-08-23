# Run OAuth2 Persistence Cleanup

Expired OAuth2 records must be removed independently from HTTP request
handling. Running cleanup in every ASGI worker duplicates work and turns the
web-process count into an accidental scheduler configuration.

Zero Auth Lite therefore provides a dedicated executable:

```bash
uv run python -m app.oauth2.cleanup_worker
```

Database foreign keys protect the ownership boundaries independently of this
worker. Deleting a user removes its browser sessions, OAuth2 sessions, token
families, and pending authorization artifacts. Deleting an OAuth2 client or a
organization likewise removes the OAuth2 artifacts that refer to it. These cascades
are an invalidation rule: no authorization code, device flow, session, or token
remains usable after its owning security principal is deleted.

It runs cleanup once at startup, then repeats according to
`ZA_OAUTH2__CLEANUP_INTERVAL_SECONDS`. The worker removes expired or
consumed authorization codes, authorization transactions, device
authorizations, SQL token pairs, and ended or orphaned OAuth2 sessions. When
the worker removes an expired token pair, the now-orphaned session and its
consumed refresh-token history are removed in the same or a later bounded run
through relational cascade rules.

Run exactly one scheduler for a database. Do not run the continuous worker and
a cron job at the same time. Cleanup is idempotent, but duplicate schedulers add
database work without improving correctness.

## Docker Compose Worker

The canonical Compose stack starts `oauth2-cleanup` as a side worker from the
same image and environment as the server:

```bash
docker compose up --build
```

This is a separate container process, not a background task inside FastAPI.
Scaling the `backend` service therefore does not create more cleanup loops.

## Cron Or A Platform Scheduler

For cron, a systemd timer, or a managed scheduler, use one-shot mode:

```bash
uv run python -m app.oauth2.cleanup_worker --once
```

With Compose, invoke the same one-shot command in a temporary container:

```bash
docker compose run --rm oauth2-cleanup \
  python -m app.oauth2.cleanup_worker --once
```

Schedule that command at the desired interval and do not start the continuous
`oauth2-cleanup` service. Run Alembic migrations before either mode; the
cleanup executable checks the migration head and fails rather than operating
on an unknown schema.

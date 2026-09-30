# Run Browser-Session Cleanup

Expired and revoked browser-session rows no longer carry authority, but they
remain useful until a bounded maintenance operation removes them. Run cleanup
outside HTTP request handling so routine persistence maintenance does not
depend on an operator opening the management interface:

```bash
uv run python -m app.browser_sessions.cleanup_worker
```

The worker drains the rows that are already eligible at startup, then repeats
after `ZA_BROWSER_SESSION__CLEANUP_INTERVAL_SECONDS`. Every transaction deletes
at most `ZA_BROWSER_SESSION__CLEANUP_BATCH_SIZE` rows, and the worker yields
between batches. This keeps SQLite write transactions short while allowing a
backlog larger than one batch to make progress. Active sessions are never
selected.

Run one continuous worker for the database. For a cron job, systemd timer, or
another scheduler, use one-shot mode instead:

```bash
uv run python -m app.browser_sessions.cleanup_worker --once
```

One-shot mode drains the finite backlog that was eligible when it started,
using the same bounded transactions, and then exits.

The server API for server operators and built-in management UI can still trigger
one batch manually. The periodic worker exits without opening the database when
browser sessions are disabled.

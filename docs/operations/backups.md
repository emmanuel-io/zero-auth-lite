# Backups And Recovery

The SQLite database contains the durable identity, browser-session, OAuth2
session, token-pair, refresh-token history, workflow-token, and notification
outbox state. Back it up as one relational unit so that related lifecycle and
revocation records are restored together.

Define the backup frequency, retention, encryption, storage access, and restore
objectives for the deployment. Test restores against an isolated Zero Auth Lite
instance before relying on the procedure. After restoring, apply the complete
[migration chain](migrations.md) before starting the web process or workers.

Signing keys and environment secrets are not stored in the database. Back up
or escrow them through the deployment's secret-management system and keep the
configuration aligned with the restored data. Losing keys can invalidate
tokens; restoring old token state without its matching key and derivation-key
material does not recreate a coherent server.

Zero Auth Lite does not provide an automated backup command or disaster-recovery
orchestration. While the server is running, use SQLite's online backup API or
the `sqlite3` CLI `.backup` command against the configured database. These
mechanisms take a consistent snapshot while WAL mode is active.

Alternatively, stop the web process and both workers completely before copying
the database files. Never copy only the main `.db` file from a running server:
committed changes may still be present in the `-wal` file, so such a copy can be
incomplete. Keep the backup destination outside the live database directory,
then validate integrity and perform a restore rehearsal on an isolated copy.

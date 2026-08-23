"""Helpers for the canonical server's relational schema migrations."""

from pathlib import Path
from typing import TYPE_CHECKING

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy.ext.asyncio import AsyncEngine


if TYPE_CHECKING:
    from sqlalchemy.engine import Connection


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _expected_migration_heads() -> frozenset[str]:
    """Return the Alembic heads shipped with this server checkout."""
    config = Config(PROJECT_ROOT / "alembic.ini")
    config.set_main_option("script_location", str(PROJECT_ROOT / "alembic"))
    return frozenset(ScriptDirectory.from_config(config).get_heads())


def _database_migration_heads(sync_connection: "Connection") -> frozenset[str]:
    """Return the Alembic heads currently recorded in the database."""
    context = MigrationContext.configure(sync_connection)
    return frozenset(context.get_current_heads())


def _require_current_migration_heads(
    *,
    current_heads: frozenset[str],
    expected_heads: frozenset[str],
) -> None:
    """Reject an uninitialized or out-of-date database schema."""
    if current_heads == expected_heads:
        return
    command = "uv run alembic upgrade head"
    if not current_heads:
        msg = (
            "Database schema is not initialized with Alembic. "
            f"Run `{command}` before starting the server."
        )
        raise RuntimeError(msg)

    current = ", ".join(sorted(current_heads))
    expected = ", ".join(sorted(expected_heads))
    msg = (
        f"Database schema is out of date (current: {current}; expected: {expected}). "
        f"Run `{command}` before starting the server."
    )
    raise RuntimeError(msg)


async def ensure_database_is_migrated(engine: AsyncEngine) -> None:
    """Fail fast unless the database is at the checkout's Alembic heads."""
    expected_heads = _expected_migration_heads()
    async with engine.connect() as connection:
        current_heads = await connection.run_sync(_database_migration_heads)
    _require_current_migration_heads(
        current_heads=current_heads,
        expected_heads=expected_heads,
    )

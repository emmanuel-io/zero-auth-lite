"""SQLAlchemy engine and session-factory setup for the canonical server."""

from pathlib import Path
from typing import Any, cast, TYPE_CHECKING

from sqlalchemy import event
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncEngine, create_async_engine


if TYPE_CHECKING:
    from sqlalchemy.engine import Connection
    from sqlalchemy.engine.interfaces import DBAPIConnection
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession


def sqlite_url(db_path: Path) -> URL:
    """Build the canonical asynchronous SQLite URL for a database path."""
    return URL.create(drivername="sqlite+aiosqlite", database=str(db_path))


def create_engine(db_path: Path, *, echo: bool = False) -> "AsyncEngine":
    """Build a new AsyncEngine.

    Args:
        db_path (Path): Path to the SQLite database file.
        echo (bool): Whether SQLAlchemy should log emitted SQL.

    Returns:
        AsyncEngine: Configured async engine.
    """
    engine = create_async_engine(
        url=sqlite_url(db_path),
        echo=echo,
    )

    @event.listens_for(engine.sync_engine, "connect")
    def configure_sqlite_connection(
        dbapi_connection: object,
        _connection_record: object,
    ) -> None:
        """Apply canonical SQLite pragmas for local server reliability."""
        # Disable sqlite3's implicit BEGIN. The SQLAlchemy begin listener below
        # then opens every transaction explicitly, including read-first flows.
        cast("Any", dbapi_connection).isolation_level = None
        cursor = cast("DBAPIConnection", dbapi_connection).cursor()
        try:
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    @event.listens_for(engine.sync_engine, "begin")
    def begin_sqlite_transaction(connection: "Connection") -> None:
        """Start every SQLite transaction explicitly, including read-first flows."""
        connection.exec_driver_sql("BEGIN")

    return engine


def create_session_factory(
    engine: "AsyncEngine",
) -> "async_sessionmaker[AsyncSession]":
    """Create a session factory bound to engine.

    Args:
        engine (AsyncEngine): Shared process engine.

    Returns:
        async_sessionmaker[AsyncSession]: Session factory.
    """
    return async_sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )

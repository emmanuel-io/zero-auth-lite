"""Database lifecycle helpers for dedicated workers."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from app.db.engine import create_engine, create_session_factory
from app.db.migrations import ensure_database_is_migrated


if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

    from app.settings.root import Settings


@asynccontextmanager
async def open_worker_database(
    settings: "Settings",
) -> AsyncIterator["async_sessionmaker[AsyncSession]"]:
    """Open one migrated worker database and always dispose its engine."""
    engine = create_engine(settings.db_path, echo=settings.db_echo)
    try:
        await ensure_database_is_migrated(engine)
        yield create_session_factory(engine)
    finally:
        await engine.dispose()

"""SQLAlchemy session dependency."""

import sqlite3
from contextlib import asynccontextmanager
from typing import Annotated, cast, TYPE_CHECKING

from fastapi import Depends, Request
from sqlalchemy.exc import OperationalError

from app.db.errors import DatabaseBusyError


if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession


def is_sqlite_busy_error(exc: OperationalError) -> bool:
    """Return whether a SQLAlchemy operation failed with SQLite BUSY state."""
    sqlite_error = exc.orig
    error_code = getattr(sqlite_error, "sqlite_errorcode", None)
    if isinstance(error_code, int):
        return error_code & 0xFF == sqlite3.SQLITE_BUSY
    message = str(sqlite_error).casefold()
    return "database is locked" in message or "database is busy" in message


@asynccontextmanager
async def database_session(request: Request) -> "AsyncIterator[AsyncSession]":
    """Open a SQLAlchemy session that commits on success and rolls back on error."""
    session_factory = request.app.state.core_session_factory
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except OperationalError as exc:
            await session.rollback()
            if is_sqlite_busy_error(exc):
                raise DatabaseBusyError from exc
            raise
        except Exception:
            await session.rollback()
            raise


async def get_db_session(request: Request) -> "AsyncIterator[AsyncSession]":
    """Yield a request-scoped SQLAlchemy session."""
    async with database_session(request) as session:
        yield session


def get_db_session_factory(request: Request) -> "async_sessionmaker[AsyncSession]":
    """Return the canonical factory for explicit independent transactions."""
    return cast(
        "async_sessionmaker[AsyncSession]", request.app.state.core_session_factory
    )


@asynccontextmanager
async def independent_transaction(
    session_factory: "async_sessionmaker[AsyncSession]",
) -> "AsyncIterator[AsyncSession]":
    """Open a new session whose transaction commits only on normal exit."""
    async with session_factory.begin() as session:
        yield session


DbSessionDep = Annotated[
    "AsyncSession",
    Depends(get_db_session, scope="function"),
]
"""Alias for injecting an AsyncSession.
Usage:
    def route(db_session: DbSessionDep):
        ...
"""

DbSessionFactoryDep = Annotated[
    "async_sessionmaker[AsyncSession]",
    Depends(get_db_session_factory),
]

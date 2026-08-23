"""Behavior tests for database dependencies."""

import sqlite3

import pytest
from app.core.errors.handlers import app_error_handler
from app.db.dependencies import DbSessionDep
from app.db.errors import DatabaseBusyError
from app.settings.root import Settings
from app.settings.state import set_settings_snapshot
from fastapi import FastAPI, status
from httpx import ASGITransport, AsyncClient
from sqlalchemy.exc import OperationalError


pytestmark = pytest.mark.unit


class _FailingSession:
    """Minimal session whose commit exposes transaction ordering."""

    def __init__(self, error: Exception | None = None) -> None:
        """Configure the exception raised while committing."""
        self.rollback_called = False
        self.error = error or RuntimeError("commit failed")

    async def commit(self) -> None:
        """Simulate a database failure during commit."""
        raise self.error

    async def rollback(self) -> None:
        """Record rollback after the failed commit."""
        self.rollback_called = True


class _SessionContext:
    """Minimal async context manager returned by a session factory."""

    def __init__(self, session: _FailingSession) -> None:
        self.session = session

    async def __aenter__(self) -> _FailingSession:
        """Return the fake session."""
        return self.session

    async def __aexit__(self, *_args: object) -> None:
        """Leave cleanup to the dependency under test."""


@pytest.mark.asyncio
async def test_commit_failure_happens_before_response_is_sent() -> None:
    """A failed commit must replace the successful endpoint response."""
    session = _FailingSession()
    app = FastAPI()
    app.state.core_session_factory = lambda: _SessionContext(session)
    set_settings_snapshot(app, Settings())

    @app.post("/items", status_code=status.HTTP_201_CREATED)
    async def create_item(_db_session: DbSessionDep) -> dict[str, bool]:
        return {"created": True}

    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://testserver",
    ) as client:
        response = await client.post("/items")

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert session.rollback_called is True


@pytest.mark.asyncio
async def test_sqlite_busy_commit_returns_retryable_service_unavailable() -> None:
    """Translate transient SQLite writer contention before sending the response."""
    sqlite_error = sqlite3.OperationalError("database is locked")
    session = _FailingSession(OperationalError("COMMIT", {}, sqlite_error))
    app = FastAPI()
    app.state.core_session_factory = lambda: _SessionContext(session)
    set_settings_snapshot(app, Settings())
    app.add_exception_handler(DatabaseBusyError, app_error_handler)

    @app.post("/items", status_code=status.HTTP_201_CREATED)
    async def create_item(_db_session: DbSessionDep) -> dict[str, bool]:
        return {"created": True}

    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://testserver",
    ) as client:
        response = await client.post("/items")

    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert response.headers["retry-after"] == "1"
    assert response.json()["code"] == "DATABASE_BUSY"
    assert session.rollback_called is True

"""Unit tests for the dedicated browser-session cleanup process."""

from typing import Self

import pytest
from app.settings.root import Settings

from app.browser_sessions import cleanup_worker
from app.db import worker as db_worker


pytestmark = pytest.mark.unit


class FakeEngine:
    """Record disposal of the cleanup process engine."""

    def __init__(self) -> None:
        """Initialize disposal state."""
        self.disposed = False

    async def dispose(self) -> None:
        """Record engine disposal."""
        self.disposed = True


class FakeSessionContext:
    """Minimal asynchronous database-session context."""

    async def __aenter__(self) -> Self:
        """Return the fake session."""
        return self

    async def __aexit__(self, *_args: object) -> None:
        """Close the fake session."""


def test_cleanup_worker_parses_one_shot_mode() -> None:
    """Expose an explicit command suitable for schedulers."""
    assert cleanup_worker._parse_args(["--once"]).once is True  # noqa: SLF001
    assert cleanup_worker._parse_args([]).once is False  # noqa: SLF001


@pytest.mark.asyncio
async def test_cleanup_process_runs_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """Use canonical settings for one cleanup and always dispose its engine."""
    engine = FakeEngine()
    cleanup_calls: list[object] = []

    async def fake_migration_check(_engine: object) -> None:
        return None

    async def fake_cleanup(session_factory: object, **_kwargs: object) -> int:
        cleanup_calls.append(session_factory)
        return 0

    monkeypatch.setattr(db_worker, "create_engine", lambda *_args, **_kwargs: engine)
    monkeypatch.setattr(db_worker, "ensure_database_is_migrated", fake_migration_check)
    monkeypatch.setattr(
        db_worker, "create_session_factory", lambda _engine: FakeSessionContext
    )
    monkeypatch.setattr(cleanup_worker, "drain_browser_session_cleanup", fake_cleanup)

    await cleanup_worker.run_cleanup_process(Settings(), once=True)

    assert len(cleanup_calls) == 1
    assert cleanup_calls[0] is FakeSessionContext
    assert engine.disposed is True

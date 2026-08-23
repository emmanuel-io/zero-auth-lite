"""Unit tests for the dedicated OAuth2 cleanup process."""

from typing import Self

import pytest
from app.settings.root import Settings

from app.oauth2 import cleanup_worker


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
    """Expose an explicit command suitable for cron schedulers."""
    assert cleanup_worker._parse_args(["--once"]).once is True  # noqa: SLF001
    assert cleanup_worker._parse_args([]).once is False  # noqa: SLF001


@pytest.mark.asyncio
async def test_cleanup_process_runs_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use canonical settings for one cleanup and always dispose its engine."""
    engine = FakeEngine()
    migration_checks: list[object] = []
    cleanup_calls: list[object] = []

    def fake_create_engine(_db_path: object, *, echo: bool) -> FakeEngine:
        assert echo is False
        return engine

    async def fake_migration_check(candidate: object) -> None:
        migration_checks.append(candidate)

    def fake_session_factory(_engine: object) -> type[FakeSessionContext]:
        return FakeSessionContext

    async def fake_cleanup(**kwargs: object) -> object:
        cleanup_calls.append(kwargs["db_session"])
        return object()

    monkeypatch.setattr(cleanup_worker, "create_engine", fake_create_engine)
    monkeypatch.setattr(
        cleanup_worker,
        "ensure_database_is_migrated",
        fake_migration_check,
    )
    monkeypatch.setattr(
        cleanup_worker,
        "create_session_factory",
        fake_session_factory,
    )
    monkeypatch.setattr(cleanup_worker, "run_oauth2_cleanup", fake_cleanup)

    await cleanup_worker.run_cleanup_process(
        Settings(),
        once=True,
    )

    assert migration_checks == [engine]
    assert len(cleanup_calls) == 1
    assert isinstance(cleanup_calls[0], FakeSessionContext)
    assert engine.disposed is True

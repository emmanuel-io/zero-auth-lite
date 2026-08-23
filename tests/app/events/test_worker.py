"""Unit tests for the dedicated outbox worker process."""

import asyncio

import pytest
from app.settings.root import Settings

from app.events import worker


pytestmark = pytest.mark.unit


class FakeEngine:
    """Record disposal of the outbox worker engine."""

    def __init__(self) -> None:
        """Initialize disposal state."""
        self.disposed = False

    async def dispose(self) -> None:
        """Record engine disposal."""
        self.disposed = True


class FakeSnowflakeLease:
    """Record release of the outbox worker Snowflake node."""

    node_id = 7

    def __init__(self) -> None:
        """Initialize release state."""
        self.released = False

    def release(self) -> None:
        """Record lease release."""
        self.released = True


@pytest.fixture
def snowflake_lease(monkeypatch: pytest.MonkeyPatch) -> FakeSnowflakeLease:
    """Replace process-global Snowflake configuration for worker unit tests."""
    lease = FakeSnowflakeLease()
    monkeypatch.setattr(worker, "acquire_snowflake_node_lease", lambda **_kwargs: lease)
    monkeypatch.setattr(worker, "configure_snowflake_generator", lambda _node_id: None)
    monkeypatch.setattr(worker, "unconfigure_snowflake_generator", lambda: None)
    return lease


@pytest.mark.asyncio
async def test_outbox_process_bounds_shutdown(
    monkeypatch: pytest.MonkeyPatch,
    snowflake_lease: FakeSnowflakeLease,
) -> None:
    """Cancel a dispatcher that ignores cooperative worker shutdown."""
    engine = FakeEngine()
    cancelled = asyncio.Event()

    monkeypatch.setattr(
        worker, "create_engine", lambda _database_path, **_kwargs: engine
    )
    monkeypatch.setattr(worker, "create_session_factory", lambda _engine: object())

    async def fake_migration_check(_engine: object) -> None:
        return None

    async def stuck_dispatcher(*_args: object, **_kwargs: object) -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    monkeypatch.setattr(worker, "ensure_database_is_migrated", fake_migration_check)
    monkeypatch.setattr(worker, "run_outbox_dispatcher", stuck_dispatcher)

    stop_event = asyncio.Event()
    stop_event.set()
    await worker.run_outbox_process(
        Settings(events={"shutdown_timeout_seconds": 0.01}),
        stop_event=stop_event,
    )

    assert cancelled.is_set()
    assert engine.disposed is True
    assert snowflake_lease.released is True

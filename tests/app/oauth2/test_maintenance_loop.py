"""Unit tests for periodic OAuth2 maintenance orchestration."""

import asyncio
from typing import Self

import pytest

from app.oauth2 import maintenance


pytestmark = pytest.mark.unit


class FakeSessionContext:
    """Minimal asynchronous session context for the maintenance loop."""

    async def __aenter__(self) -> Self:
        """Return the fake session context."""
        return self

    async def __aexit__(self, *_args: object) -> None:
        """Close the fake session context."""


@pytest.mark.asyncio
async def test_oauth2_cleanup_worker_runs_immediately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Run one cleanup immediately and stop cooperatively."""
    stop_event = asyncio.Event()
    calls: list[object] = []

    async def fake_cleanup(**kwargs: object) -> object:
        calls.append(kwargs["db_session"])
        stop_event.set()
        return object()

    monkeypatch.setattr(maintenance, "run_oauth2_cleanup", fake_cleanup)

    await maintenance.run_oauth2_cleanup_worker(
        FakeSessionContext,  # type: ignore[arg-type]
        interval_seconds=0,
        batch_size=10,
        stop_event=stop_event,
    )

    assert len(calls) == 1
    assert isinstance(calls[0], FakeSessionContext)

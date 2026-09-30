"""Unit tests for periodic browser-session maintenance orchestration."""

import asyncio
from typing import Self

import pytest
from app.browser_sessions.settings import BrowserSessionSettings

from app.browser_sessions import maintenance


pytestmark = pytest.mark.unit
EXPECTED_BATCH_COUNT = 2
EXPECTED_DELETED_COUNT = 3


class FakeSessionContext:
    """Minimal asynchronous session context for the maintenance loop."""

    async def __aenter__(self) -> Self:
        """Return the fake session context."""
        return self

    async def __aexit__(self, *_args: object) -> None:
        """Close the fake session context."""


@pytest.mark.asyncio
async def test_browser_session_cleanup_worker_runs_immediately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Run one cleanup immediately and stop cooperatively."""
    stop_event = asyncio.Event()
    calls: list[object] = []

    async def fake_cleanup(session_factory: object, **_kwargs: object) -> int:
        calls.append(session_factory)
        stop_event.set()
        return 0

    monkeypatch.setattr(maintenance, "drain_browser_session_cleanup", fake_cleanup)

    await maintenance.run_browser_session_cleanup_worker(
        FakeSessionContext,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        settings=BrowserSessionSettings(),
        stop_event=stop_event,
    )

    assert len(calls) == 1
    assert calls[0] is FakeSessionContext


@pytest.mark.asyncio
async def test_browser_session_cleanup_drains_full_batches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use short transactions until the fixed-cutoff backlog is empty."""
    results = [2, 1]
    cutoffs: list[object] = []

    async def fake_cleanup(**kwargs: object) -> int:
        cutoffs.append(kwargs["now"])
        return results.pop(0)

    monkeypatch.setattr(maintenance, "run_browser_session_cleanup", fake_cleanup)

    deleted = await maintenance.drain_browser_session_cleanup(
        FakeSessionContext,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        settings=BrowserSessionSettings(cleanup_batch_size=2),
    )

    assert deleted == EXPECTED_DELETED_COUNT
    assert len(cutoffs) == EXPECTED_BATCH_COUNT
    assert cutoffs[0] == cutoffs[1]

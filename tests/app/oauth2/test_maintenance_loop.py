"""Unit tests for periodic OAuth2 maintenance orchestration."""

import asyncio
from typing import Self

import pytest

from app.oauth2 import maintenance


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
async def test_oauth2_cleanup_worker_runs_immediately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Run one cleanup immediately and stop cooperatively."""
    stop_event = asyncio.Event()
    calls: list[object] = []

    async def fake_cleanup(session_factory: object, **_kwargs: object) -> object:
        calls.append(session_factory)
        stop_event.set()
        return object()

    monkeypatch.setattr(maintenance, "drain_oauth2_cleanup", fake_cleanup)

    await maintenance.run_oauth2_cleanup_worker(
        FakeSessionContext,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        interval_seconds=0,
        batch_size=10,
        stop_event=stop_event,
    )

    assert len(calls) == 1
    assert calls[0] is FakeSessionContext


@pytest.mark.asyncio
async def test_oauth2_cleanup_drains_full_batches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use short transactions until every fixed-cutoff batch is partial."""
    results = [
        maintenance.OAuth2CleanupResult(2, 0, 0, 0, 0),
        maintenance.OAuth2CleanupResult(1, 0, 0, 0, 0),
    ]
    cutoffs: list[object] = []

    async def fake_cleanup(**kwargs: object) -> maintenance.OAuth2CleanupResult:
        cutoffs.append(kwargs["now"])
        return results.pop(0)

    monkeypatch.setattr(maintenance, "run_oauth2_cleanup", fake_cleanup)

    result = await maintenance.drain_oauth2_cleanup(
        FakeSessionContext,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        batch_size=2,
    )

    assert result.authorization_codes == EXPECTED_DELETED_COUNT
    assert result.authorization_transactions == 0
    assert len(cutoffs) == EXPECTED_BATCH_COUNT
    assert cutoffs[0] == cutoffs[1]

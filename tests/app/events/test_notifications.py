"""Tests for outbox event serialization boundaries."""

import pytest
from app.events.base import BaseEvent
from app.events.outbox import OutboxEventPublisher


pytestmark = pytest.mark.unit


class RecordingSession:
    """Minimal session fake recording added ORM rows."""

    def __init__(self) -> None:
        """Initialize collected rows."""
        self.rows: list[object] = []

    def add(self, row: object) -> None:
        """Record an added row."""
        self.rows.append(row)

    async def flush(self) -> None:
        """Satisfy the publisher session contract."""


@pytest.mark.asyncio
async def test_unknown_application_event_is_not_enqueued() -> None:
    """Reject unsupported events instead of silently losing them."""
    session = RecordingSession()

    with pytest.raises(TypeError, match="Unsupported outbox event type"):
        await OutboxEventPublisher(session).publish(  # type: ignore[arg-type]
            BaseEvent(event_type="unknown.event")
        )

    assert session.rows == []

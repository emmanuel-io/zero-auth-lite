"""Tests for transactional event dependency wiring."""

import pytest
from app.events.dependencies import get_event_publisher
from app.events.outbox import OutboxEventPublisher


pytestmark = pytest.mark.unit


def test_event_dependency_uses_request_database_session() -> None:
    """Bind the outbox publisher to the caller's transaction."""
    session = object()

    publisher = get_event_publisher(session)  # type: ignore[arg-type]

    assert isinstance(publisher, OutboxEventPublisher)
    assert publisher.db_session is session

"""Tests for transactional event dependency wiring."""

import pytest
from app.notifications.dependencies import get_notification_publisher
from app.notifications.publisher import NotificationOutboxPublisher


pytestmark = pytest.mark.unit


def test_event_dependency_uses_request_database_session() -> None:
    """Bind the outbox publisher to the caller's transaction."""
    session = object()

    publisher = get_notification_publisher(
        session  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
    )

    assert isinstance(publisher, NotificationOutboxPublisher)
    assert publisher.db_session is session

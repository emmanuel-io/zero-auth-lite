"""Tests for notification event boundaries."""

from unittest.mock import Mock

import pytest
from app.notifications.builder import (
    AuthNotificationBuilder,
    UnsupportedNotificationEventError,
)
from app.notifications.event import NotificationEvent
from app.notifications.events import NOTIFICATION_EVENT_CLASSES
from app.settings.ui import UIURLs
from app.workflow_tokens.service import WorkflowTokenService
from sqlalchemy.ext.asyncio import AsyncSession


pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_notification_builder_rejects_unhandled_event() -> None:
    """Do not mistake a missing registered-event handler for a stale target."""
    builder = AuthNotificationBuilder(
        db_session=Mock(spec=AsyncSession),
        workflow_token_service=Mock(spec=WorkflowTokenService),
        workflow_urls=UIURLs(),
    )

    with pytest.raises(
        UnsupportedNotificationEventError,
        match=r"Unsupported notification event type: unknown\.event",
    ):
        await builder.build(NotificationEvent(event_type="unknown.event"))


def test_notification_builder_requires_a_handler_for_every_registered_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject a notification registry that has no exhaustive dispatch table."""
    monkeypatch.setattr(
        "app.notifications.builder.NOTIFICATION_EVENT_CLASSES",
        (*NOTIFICATION_EVENT_CLASSES, NotificationEvent),
    )

    with pytest.raises(
        UnsupportedNotificationEventError,
        match="Notification builders must match the registered event classes",
    ):
        AuthNotificationBuilder(
            db_session=Mock(spec=AsyncSession),
            workflow_token_service=Mock(spec=WorkflowTokenService),
            workflow_urls=UIURLs(),
        )

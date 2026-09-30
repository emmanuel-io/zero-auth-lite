"""Tests for the transactional authentication-notification publisher."""

import pytest
from app.db.models.notification_outbox import NotificationOutboxDB
from app.notifications.event import NotificationEvent
from app.notifications.events import (
    InviteCreated,
    NOTIFICATION_EVENT_CLASSES,
    NOTIFICATION_EVENT_REGISTRY,
    PasswordResetRequested,
)
from app.notifications.publisher import NotificationOutboxPublisher
from asgi_correlation_id.context import correlation_id as correlation_id_context
from fastapi import FastAPI
from sqlalchemy import func, select

from tests.identifiers import PublicId


pytestmark = pytest.mark.integration
USER_PUBLIC_ID = PublicId(123)
USER_EMAIL_ID = 456


def test_notification_event_registry_maps_every_supported_class() -> None:
    """Keep persisted event names derived from the supported event classes."""
    assert tuple(NOTIFICATION_EVENT_REGISTRY.values()) == NOTIFICATION_EVENT_CLASSES
    assert set(NOTIFICATION_EVENT_REGISTRY) == {
        event_class.model_fields["event_type"].default
        for event_class in NOTIFICATION_EVENT_CLASSES
    }


@pytest.mark.asyncio
async def test_outbox_event_is_committed_with_the_caller_transaction(
    app: FastAPI,
) -> None:
    """Persist an event only when its surrounding transaction commits."""
    async with app.state.core_session_factory() as session:
        event = PasswordResetRequested(
            user_public_id=USER_PUBLIC_ID,
            user_email_id=USER_EMAIL_ID,
        )
        await NotificationOutboxPublisher(session).publish(event)
        await session.commit()

    async with app.state.core_session_factory() as session:
        row = await session.scalar(
            select(NotificationOutboxDB).where(
                NotificationOutboxDB.event_id == event.event_id
            )
        )

    assert row is not None
    assert row.payload["user_public_id"] == str(USER_PUBLIC_ID)
    assert row.payload["user_email_id"] == USER_EMAIL_ID
    assert "token" not in row.payload


@pytest.mark.asyncio
async def test_outbox_event_captures_request_correlation_id(app: FastAPI) -> None:
    """Persist causal request context outside the notification payload."""
    request_correlation_id = "b" * 32
    correlation_token = correlation_id_context.set(request_correlation_id)
    try:
        async with app.state.core_session_factory() as session:
            event = PasswordResetRequested(
                user_public_id=PublicId(123),
                user_email_id=USER_EMAIL_ID,
            )
            await NotificationOutboxPublisher(session).publish(event)
            await session.commit()
    finally:
        correlation_id_context.reset(correlation_token)

    async with app.state.core_session_factory() as session:
        row = await session.scalar(
            select(NotificationOutboxDB).where(
                NotificationOutboxDB.event_id == event.event_id
            )
        )

    assert row is not None
    assert row.correlation_id == request_correlation_id
    assert "correlation_id" not in row.payload


@pytest.mark.asyncio
async def test_outbox_event_rolls_back_with_the_caller_transaction(
    app: FastAPI,
) -> None:
    """Do not leak an event from a rolled-back composed command."""
    async with app.state.core_session_factory() as session:
        await NotificationOutboxPublisher(session).publish(
            InviteCreated(user_public_id=PublicId(123), user_email_id=USER_EMAIL_ID)
        )
        await session.rollback()

    async with app.state.core_session_factory() as session:
        count = await session.scalar(
            select(func.count()).select_from(NotificationOutboxDB)
        )

    assert count == 0


@pytest.mark.asyncio
async def test_outbox_rejects_unsupported_event_types(app: FastAPI) -> None:
    """Fail visibly when a caller publishes an event without a handler."""
    async with app.state.core_session_factory() as session:
        with pytest.raises(TypeError, match="Unsupported outbox event type"):
            await NotificationOutboxPublisher(session).publish(
                NotificationEvent(event_type="unsupported.event")
            )

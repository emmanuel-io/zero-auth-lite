"""Tests for the transactional authentication-event publisher."""

import pytest
from app.db.models.auth_event import AuthEventOutboxDB
from app.events.base import BaseEvent
from app.events.outbox import OutboxEventPublisher
from app.events.types import InviteCreated, PasswordResetRequested
from app.public_ids import PublicId
from asgi_correlation_id.context import correlation_id as correlation_id_context
from fastapi import FastAPI
from sqlalchemy import func, select


pytestmark = pytest.mark.integration
USER_PUBLIC_ID = 123
USER_EMAIL_ID = 456


@pytest.mark.asyncio
async def test_outbox_event_is_committed_with_the_caller_transaction(
    app: FastAPI,
) -> None:
    """Persist an event only when its surrounding transaction commits."""
    async with app.state.core_session_factory() as session:
        event = PasswordResetRequested(
            user_public_id=PublicId(123),
            user_email_id=USER_EMAIL_ID,
        )
        await OutboxEventPublisher(session).publish(event)
        await session.commit()

    async with app.state.core_session_factory() as session:
        row = await session.scalar(
            select(AuthEventOutboxDB).where(
                AuthEventOutboxDB.event_id == event.event_id
            )
        )

    assert row is not None
    assert row.payload["user_public_id"] == USER_PUBLIC_ID
    assert row.payload["user_email_id"] == USER_EMAIL_ID
    assert "token" not in row.payload


@pytest.mark.asyncio
async def test_outbox_event_captures_request_correlation_id(app: FastAPI) -> None:
    """Persist causal request context outside the domain-event payload."""
    request_correlation_id = "b" * 32
    correlation_token = correlation_id_context.set(request_correlation_id)
    try:
        async with app.state.core_session_factory() as session:
            event = PasswordResetRequested(
                user_public_id=PublicId(123),
                user_email_id=USER_EMAIL_ID,
            )
            await OutboxEventPublisher(session).publish(event)
            await session.commit()
    finally:
        correlation_id_context.reset(correlation_token)

    async with app.state.core_session_factory() as session:
        row = await session.scalar(
            select(AuthEventOutboxDB).where(
                AuthEventOutboxDB.event_id == event.event_id
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
        await OutboxEventPublisher(session).publish(
            InviteCreated(user_public_id=PublicId(123), user_email_id=USER_EMAIL_ID)
        )
        await session.rollback()

    async with app.state.core_session_factory() as session:
        count = await session.scalar(
            select(func.count()).select_from(AuthEventOutboxDB)
        )

    assert count == 0


@pytest.mark.asyncio
async def test_outbox_rejects_unsupported_event_types(app: FastAPI) -> None:
    """Fail visibly when a caller publishes an event without a handler."""
    async with app.state.core_session_factory() as session:
        with pytest.raises(TypeError, match="Unsupported outbox event type"):
            await OutboxEventPublisher(session).publish(
                BaseEvent(event_type="unsupported.event")
            )

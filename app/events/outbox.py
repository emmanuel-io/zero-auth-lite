"""Transactional publisher for durable authentication notifications."""

from asgi_correlation_id.context import correlation_id as correlation_id_context
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.auth_event import AuthEventOutboxDB
from app.events.base import BaseEvent
from app.events.types import (
    AccountVerificationRequested,
    EmailChangeRequested,
    InviteCreated,
    PasswordResetRequested,
)


NOTIFICATION_EVENTS = (
    AccountVerificationRequested,
    EmailChangeRequested,
    InviteCreated,
    PasswordResetRequested,
)


class OutboxEventPublisher:
    """Persist notification events without executing external side effects."""

    def __init__(self, db_session: AsyncSession) -> None:
        """Initialize the publisher with the caller's transaction."""
        self.db_session = db_session

    async def publish(self, event: BaseEvent) -> None:
        """Add a supported event to the current SQLAlchemy transaction."""
        if not isinstance(event, NOTIFICATION_EVENTS):
            msg = f"Unsupported outbox event type: {event.event_type}"
            raise TypeError(msg)
        self.db_session.add(
            AuthEventOutboxDB(
                event_id=event.event_id,
                event_type=event.event_type,
                correlation_id=correlation_id_context.get(),
                payload=event.model_dump(mode="json"),
                occurred_at=event.occurred_at,
                available_at=event.occurred_at,
            )
        )
        await self.db_session.flush()

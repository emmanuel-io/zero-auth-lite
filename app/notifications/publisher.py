"""Transactional publisher for durable authentication notifications."""

from asgi_correlation_id.context import correlation_id as correlation_id_context
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.notification_outbox import NotificationOutboxDB
from app.notifications.event import NotificationEvent
from app.notifications.events import NOTIFICATION_EVENT_CLASSES


class NotificationOutboxPublisher:
    """Persist notification events without executing external side effects."""

    def __init__(self, db_session: AsyncSession) -> None:
        """Initialize the publisher with the caller's transaction."""
        self.db_session = db_session

    async def publish(self, event: NotificationEvent) -> None:
        """Add a supported event to the current SQLAlchemy transaction."""
        if not isinstance(event, NOTIFICATION_EVENT_CLASSES):
            msg = f"Unsupported outbox event type: {event.event_type}"
            raise TypeError(msg)
        self.db_session.add(
            NotificationOutboxDB(
                event_id=event.event_id,
                event_type=event.event_type,
                correlation_id=correlation_id_context.get(),
                payload=event.model_dump(mode="json"),
                occurred_at=event.occurred_at,
                available_at=event.occurred_at,
            )
        )
        await self.db_session.flush()

"""Event publisher protocol."""

from typing import Protocol

from app.events.base import BaseEvent


class EventPublisher(Protocol):
    """Protocol for persisting application events in the current transaction."""

    async def publish(self, event: BaseEvent) -> None:
        """Persist a domain event without executing external side effects."""

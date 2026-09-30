"""Transactional notification publisher protocol."""

from typing import Protocol

from app.notifications.event import NotificationEvent


class NotificationPublisher(Protocol):
    """Persist notification intentions in the current transaction."""

    async def publish(self, event: NotificationEvent) -> None:
        """Persist a notification without executing external side effects."""

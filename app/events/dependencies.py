"""FastAPI dependencies for application domain events."""

from typing import Annotated

from fastapi import Depends

from app.db.dependencies import DbSessionDep
from app.events.outbox import OutboxEventPublisher
from app.events.protocols import EventPublisher
from app.events.requests import AuthNotificationRequestService


def get_event_publisher(
    db_session: DbSessionDep,
) -> EventPublisher:
    """Provide an outbox publisher bound to the request transaction."""
    return OutboxEventPublisher(db_session)


EventPublisherDep = Annotated[EventPublisher, Depends(get_event_publisher)]


def get_auth_notification_request_service(
    db_session: DbSessionDep,
    event_publisher: EventPublisherDep,
) -> AuthNotificationRequestService:
    """Provide the anonymous authentication-notification request service."""
    return AuthNotificationRequestService(
        db_session=db_session,
        event_publisher=event_publisher,
    )


AuthNotificationRequestServiceDep = Annotated[
    AuthNotificationRequestService,
    Depends(get_auth_notification_request_service),
]

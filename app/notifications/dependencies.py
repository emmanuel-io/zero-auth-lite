"""FastAPI dependencies for authentication notifications."""

from typing import Annotated

from fastapi import Depends

from app.db.dependencies import DbSessionDep
from app.notifications.protocols import NotificationPublisher
from app.notifications.publisher import NotificationOutboxPublisher
from app.notifications.requests import AuthNotificationRequestService


def get_notification_publisher(
    db_session: DbSessionDep,
) -> NotificationPublisher:
    """Provide an outbox publisher bound to the request transaction."""
    return NotificationOutboxPublisher(db_session)


NotificationPublisherDep = Annotated[
    NotificationPublisher, Depends(get_notification_publisher)
]


def get_auth_notification_request_service(
    db_session: DbSessionDep,
    notification_publisher: NotificationPublisherDep,
) -> AuthNotificationRequestService:
    """Provide the anonymous authentication-notification request service."""
    return AuthNotificationRequestService(
        db_session=db_session,
        notification_publisher=notification_publisher,
    )


AuthNotificationRequestServiceDep = Annotated[
    AuthNotificationRequestService,
    Depends(get_auth_notification_request_service),
]

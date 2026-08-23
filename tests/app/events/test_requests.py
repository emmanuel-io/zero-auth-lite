"""Tests for opaque authentication-notification request resolution."""

import pytest
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.events.base import BaseEvent
from app.events.requests import AuthNotificationRequestService
from app.events.types import AccountVerificationRequested, PasswordResetRequested
from app.identity.users.enums import UserEmailStatus
from fastapi import FastAPI
from sqlalchemy import insert


pytestmark = pytest.mark.integration


class FakeEventPublisher:
    """Record resolved events without persisting an outbox row."""

    def __init__(self) -> None:
        """Initialize empty event storage."""
        self.events: list[BaseEvent] = []

    async def publish(self, event: BaseEvent) -> None:
        """Record one resolved event."""
        self.events.append(event)


@pytest.mark.asyncio
async def test_requests_bind_events_to_the_current_account(app: FastAPI) -> None:
    """Capture both the stable account identifier and its expected email."""
    publisher = FakeEventPublisher()
    async with app.state.core_session_factory() as session:
        organization_id = await session.scalar(
            insert(OrganizationDB)
            .values(name="Request Organization")
            .returning(OrganizationDB.id)
        )
        assert organization_id is not None
        user = (
            await session.execute(
                insert(UserDB)
                .values(
                    hashed_password="hash",  # noqa: S106
                    is_active=True,
                )
                .returning(UserDB)
            )
        ).scalar_one()
        user_email_id = await session.scalar(
            insert(UserEmailDB)
            .values(
                user_id=user.id,
                email="request@example.com",
                normalized_email="request@example.com",
                status=UserEmailStatus.CURRENT,
            )
            .returning(UserEmailDB.id)
        )
        assert user_email_id is not None
        session.add(
            OrganizationMembershipDB(
                user_id=user.id,
                organization_id=organization_id,
            )
        )
        requests = AuthNotificationRequestService(
            db_session=session,
            event_publisher=publisher,
        )

        await requests.request_account_verification("REQUEST@example.com")
        await requests.request_password_reset("request@example.com")

    verification, password_reset = publisher.events
    assert isinstance(verification, AccountVerificationRequested)
    assert verification.user_public_id == user.public_id
    assert verification.user_email_id == user_email_id
    assert isinstance(password_reset, PasswordResetRequested)
    assert password_reset.user_public_id == user.public_id
    assert password_reset.user_email_id == user_email_id


@pytest.mark.asyncio
async def test_unknown_email_keeps_request_opaque_without_event(app: FastAPI) -> None:
    """Silently ignore an unknown address so adapters can return the same response."""
    publisher = FakeEventPublisher()
    async with app.state.core_session_factory() as session:
        requests = AuthNotificationRequestService(
            db_session=session,
            event_publisher=publisher,
        )

        await requests.request_account_verification("missing@example.com")
        await requests.request_password_reset("missing@example.com")

    assert publisher.events == []

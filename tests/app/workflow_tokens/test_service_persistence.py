"""Integration tests for persisted workflow-token behavior."""

import asyncio
from datetime import datetime, UTC

import pytest
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.enums import UserEmailStatus
from app.workflow_tokens.enums import WorkflowTokenPurpose
from app.workflow_tokens.errors import InvalidWorkflowTokenError
from app.workflow_tokens.service import WorkflowTokenService
from app.workflow_tokens.settings import WorkflowTokenSettings
from fastapi import FastAPI
from sqlalchemy import insert


pytestmark = pytest.mark.integration


async def seed_user(app: FastAPI, *, email: str) -> int:
    """Create the email row that owns identity workflow tokens."""
    async with app.state.core_session_factory() as db_session:
        organization = (
            await db_session.execute(
                insert(OrganizationDB)
                .values(name=f"Organization {email}")
                .returning(OrganizationDB)
            )
        ).scalar_one()
        user = (
            await db_session.execute(
                insert(UserDB)
                .values(
                    hashed_password="unused-password-hash",  # noqa: S106
                    is_active=True,
                )
                .returning(UserDB)
            )
        ).scalar_one()
        user_email = (
            await db_session.execute(
                insert(UserEmailDB)
                .values(
                    user_id=user.id,
                    email=email,
                    normalized_email=email.lower(),
                    status=UserEmailStatus.CURRENT,
                    verified_at=datetime.now(UTC),
                )
                .returning(UserEmailDB)
            )
        ).scalar_one()
        db_session.add(
            OrganizationMembershipDB(
                user_id=user.id,
                organization_id=organization.id,
            )
        )
        await db_session.commit()
        return int(user_email.id)


@pytest.mark.asyncio
async def test_workflow_token_service_replaces_and_consumes_once(app: FastAPI) -> None:
    """Assert replacement, purpose checks, and atomic one-time consumption."""
    user_email_id = await seed_user(app, email="consume@example.com")
    async with app.state.core_session_factory() as db_session:
        service = WorkflowTokenService(
            db_session=db_session, settings=WorkflowTokenSettings()
        )
        first = await service.issue_token_for_event(
            event_id="1" * 32,
            event_occurred_at=datetime.now(UTC),
            user_email_id=user_email_id,
            purpose=WorkflowTokenPurpose.VERIFY_EMAIL,
        )
        second = await service.issue_token_for_event(
            event_id="2" * 32,
            event_occurred_at=datetime.now(UTC),
            user_email_id=user_email_id,
            purpose=WorkflowTokenPurpose.VERIFY_EMAIL,
        )
        assert first is not None
        assert second is not None

        with pytest.raises(InvalidWorkflowTokenError):
            await service.consume_token(
                token=first,
                purposes=frozenset({WorkflowTokenPurpose.VERIFY_EMAIL}),
            )
        with pytest.raises(InvalidWorkflowTokenError):
            await service.consume_token(
                token=second,
                purposes=frozenset({WorkflowTokenPurpose.RESET_PASSWORD}),
            )
        consumed = await service.consume_token(
            token=second,
            purposes=frozenset({WorkflowTokenPurpose.VERIFY_EMAIL}),
        )

        assert consumed.user_email_id == user_email_id
        assert consumed.used_at is not None
        with pytest.raises(InvalidWorkflowTokenError):
            await service.consume_token(
                token=second,
                purposes=frozenset({WorkflowTokenPurpose.VERIFY_EMAIL}),
            )


@pytest.mark.asyncio
async def test_workflow_token_service_reuses_unique_source_event(app: FastAPI) -> None:
    """Look up the persisted token metadata used by an outbox retry."""
    user_email_id = await seed_user(app, email="event@example.com")
    async with app.state.core_session_factory() as db_session:
        service = WorkflowTokenService(
            db_session=db_session, settings=WorkflowTokenSettings()
        )
        occurred_at = datetime.now(UTC)
        created = await service.issue_token_for_event(
            event_id="e" * 32,
            event_occurred_at=occurred_at,
            user_email_id=user_email_id,
            purpose=WorkflowTokenPurpose.INVITE,
        )
        await db_session.commit()
        retried = await service.issue_token_for_event(
            event_id="e" * 32,
            event_occurred_at=occurred_at,
            user_email_id=user_email_id,
            purpose=WorkflowTokenPurpose.INVITE,
        )

    assert retried == created


@pytest.mark.asyncio
async def test_workflow_token_service_consumes_concurrently_only_once(
    app: FastAPI,
) -> None:
    """Allow only one transaction to consume the same workflow token."""
    user_email_id = await seed_user(app, email="concurrent@example.com")
    async with app.state.core_session_factory() as db_session:
        service = WorkflowTokenService(
            db_session=db_session, settings=WorkflowTokenSettings()
        )
        token = await service.issue_token_for_event(
            event_id="3" * 32,
            event_occurred_at=datetime.now(UTC),
            user_email_id=user_email_id,
            purpose=WorkflowTokenPurpose.RESET_PASSWORD,
        )
        assert token is not None
        await db_session.commit()

    async def consume_once() -> bool:
        async with app.state.core_session_factory() as db_session:
            service = WorkflowTokenService(
                db_session=db_session, settings=WorkflowTokenSettings()
            )
            try:
                await service.consume_token(
                    token=token,
                    purposes=frozenset({WorkflowTokenPurpose.RESET_PASSWORD}),
                )
                await db_session.commit()
            except InvalidWorkflowTokenError:
                return False
            return True

    results = await asyncio.gather(consume_once(), consume_once())

    assert results.count(True) == 1

"""Verify token retention preserves pending-delivery security state."""

import asyncio
from datetime import datetime, timedelta, UTC

import pytest
import pytest_asyncio
from app.db.models.notification_outbox import NotificationOutboxDB
from app.db.models.user import UserDB, UserEmailDB
from app.db.models.workflow_token import UserWorkflowTokenDB
from app.notifications.events import AccountVerificationRequested
from app.notifications.publisher import NotificationOutboxPublisher
from app.notifications.specs import OutboxProcessingResult
from app.workflow_tokens.enums import WorkflowTokenPurpose
from app.workflow_tokens.maintenance import drain_workflow_token_cleanup
from app.workflow_tokens.service import WorkflowTokenService
from fastapi import FastAPI
from sqlalchemy import insert, select, update

from tests.fixtures.auth import UserCredentials


pytestmark = pytest.mark.integration
RETENTION_SECONDS = 604_800


@pytest_asyncio.fixture
async def verification_event(
    app: FastAPI, verified_user_credentials: UserCredentials
) -> AccountVerificationRequested:
    """Build a notification for the seeded email without publishing it."""
    async with app.state.core_session_factory() as session:
        user_public_id, email_id = (
            await session.execute(
                select(UserDB.public_id, UserEmailDB.id)
                .join(UserEmailDB, UserEmailDB.user_id == UserDB.id)
                .where(UserEmailDB.email == verified_user_credentials.email)
            )
        ).one()
    return AccountVerificationRequested(
        user_public_id=user_public_id, user_email_id=email_id
    )


async def _cleanup(app: FastAPI, *, stop_event: asyncio.Event | None = None) -> int:
    """Drain retained tokens one row per transaction."""
    return await drain_workflow_token_cleanup(
        app.state.core_session_factory,
        retention_seconds=RETENTION_SECONDS,
        batch_size=1,
        stop_event=stop_event or asyncio.Event(),
    )


@pytest.mark.asyncio
async def test_cleanup_drains_only_old_terminal_tokens(
    app: FastAPI, verification_event: AccountVerificationRequested
) -> None:
    """Preserve live and recently terminal tokens while draining old batches."""
    now = datetime.now(UTC)
    old = now - timedelta(seconds=RETENTION_SECONDS + 60)
    future = now + timedelta(days=1)
    token_states = [
        (old, None),
        (future, old),
        (now - timedelta(seconds=60), None),
        (future, now),
        (future, None),
    ]
    async with app.state.core_session_factory.begin() as session:
        await NotificationOutboxPublisher(session).publish(
            verification_event.model_copy(
                update={"user_email_id": verification_event.user_email_id + 1}
            )
        )
        for index, (expires_at, used_at) in enumerate(token_states):
            await session.execute(
                insert(UserWorkflowTokenDB).values(
                    user_email_id=verification_event.user_email_id,
                    purpose=WorkflowTokenPurpose.VERIFY_EMAIL,
                    token_hash=str(index).zfill(64),
                    expires_at=expires_at,
                    used_at=used_at,
                )
            )
    stopped = asyncio.Event()
    stopped.set()
    assert await _cleanup(app, stop_event=stopped) == 0
    expected_deleted = 2
    assert await _cleanup(app) == expected_deleted
    async with app.state.core_session_factory() as session:
        remaining = set(await session.scalars(select(UserWorkflowTokenDB.token_hash)))
    assert remaining == {str(index).zfill(64) for index in range(2, len(token_states))}


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [{}, {"user_email_id": None}])
async def test_pending_payload_without_email_does_not_block_cleanup(
    app: FastAPI,
    verification_event: AccountVerificationRequested,
    payload: dict[str, object],
) -> None:
    """Ignore missing email IDs without letting SQL NULL block every deletion."""
    old = datetime.now(UTC) - timedelta(seconds=RETENTION_SECONDS + 60)
    async with app.state.core_session_factory.begin() as session:
        await NotificationOutboxPublisher(session).publish(verification_event)
        await session.execute(update(NotificationOutboxDB).values(payload=payload))
        await session.execute(
            insert(UserWorkflowTokenDB).values(
                user_email_id=verification_event.user_email_id,
                purpose=WorkflowTokenPurpose.VERIFY_EMAIL,
                token_hash="a" * 64,
                expires_at=old,
            )
        )
    assert await _cleanup(app) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("consumed", [False, True])
async def test_cleanup_preserves_same_event_retry_state(
    app: FastAPI,
    verification_event: AccountVerificationRequested,
    *,
    consumed: bool,
) -> None:
    """Keep a consumed marker or renew the same expired token during delivery."""
    old = datetime.now(UTC) - timedelta(seconds=RETENTION_SECONDS + 60)
    async with app.state.core_session_factory.begin() as session:
        await NotificationOutboxPublisher(session).publish(verification_event)
        service = WorkflowTokenService(
            db_session=session,
            settings=app.state.settings.identity_workflow.workflow_tokens,
        )
        token = await service.issue_token_for_event(
            event_id=verification_event.event_id,
            event_occurred_at=verification_event.occurred_at,
            user_email_id=verification_event.user_email_id,
            purpose=WorkflowTokenPurpose.VERIFY_EMAIL,
        )
        await session.execute(
            update(UserWorkflowTokenDB).values(
                expires_at=old, used_at=old if consumed else None
            )
        )
        await session.execute(
            update(NotificationOutboxDB).values(
                claimed_at=datetime.now(UTC), claimed_by="worker"
            )
        )
    assert await _cleanup(app) == 0
    async with app.state.core_session_factory.begin() as session:
        service = WorkflowTokenService(
            db_session=session,
            settings=app.state.settings.identity_workflow.workflow_tokens,
        )
        retried = await service.issue_token_for_event(
            event_id=verification_event.event_id,
            event_occurred_at=verification_event.occurred_at,
            user_email_id=verification_event.user_email_id,
            purpose=WorkflowTokenPurpose.VERIFY_EMAIL,
        )
    assert token is not None
    assert retried == (None if consumed else token)


@pytest.mark.asyncio
async def test_cleanup_preserves_newer_marker_until_older_event_finishes(
    app: FastAPI, verification_event: AccountVerificationRequested
) -> None:
    """Prevent an older queued request from replacing a newer terminal token."""
    old = datetime.now(UTC) - timedelta(seconds=RETENTION_SECONDS + 60)
    older_event = verification_event.model_copy(update={"occurred_at": old})
    async with app.state.core_session_factory.begin() as session:
        await NotificationOutboxPublisher(session).publish(older_event)
        service = WorkflowTokenService(
            db_session=session,
            settings=app.state.settings.identity_workflow.workflow_tokens,
        )
        await service.issue_token_for_event(
            event_id="f" * 32,
            event_occurred_at=old + timedelta(seconds=1),
            user_email_id=older_event.user_email_id,
            purpose=WorkflowTokenPurpose.VERIFY_EMAIL,
        )
        await session.execute(update(UserWorkflowTokenDB).values(expires_at=old))
    assert await _cleanup(app) == 0
    async with app.state.core_session_factory.begin() as session:
        service = WorkflowTokenService(
            db_session=session,
            settings=app.state.settings.identity_workflow.workflow_tokens,
        )
        assert (
            await service.issue_token_for_event(
                event_id=older_event.event_id,
                event_occurred_at=older_event.occurred_at,
                user_email_id=older_event.user_email_id,
                purpose=WorkflowTokenPurpose.VERIFY_EMAIL,
            )
            is None
        )
        await session.execute(
            update(NotificationOutboxDB).values(
                processed_at=datetime.now(UTC),
                processing_result=OutboxProcessingResult.DISCARDED_TARGET_UNAVAILABLE,
            )
        )
    assert await _cleanup(app) == 1

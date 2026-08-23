"""Integration tests for durable authentication-event dispatch."""

import asyncio
from datetime import datetime, timedelta, UTC
from unittest.mock import patch

import pytest
from app.auth_tokens.enums import AuthTokenPurpose
from app.auth_tokens.service import AuthTokenService
from app.db.models.auth_event import AuthEventOutboxDB
from app.db.models.auth_token import UserAuthTokenDB
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.events.dispatcher import (
    _claim_pending,
    cleanup_processed_events,
    dispatch_pending_once,
)
from app.events.outbox import OutboxEventPublisher
from app.events.types import AccountVerificationRequested
from app.identity.users.enums import UserEmailStatus
from app.public_ids import PublicId
from app.settings.root import Settings
from asgi_correlation_id.context import correlation_id as correlation_id_context
from fastapi import FastAPI
from pydantic import SecretStr
from sqlalchemy import func, insert, select, update


pytestmark = pytest.mark.integration
OUTBOX_CORRELATION_ID = "a" * 32


async def _seed_verification_event(app: FastAPI) -> str:
    async with app.state.core_session_factory() as session:
        organization_id = (
            await session.execute(
                insert(OrganizationDB)
                .values(name="Outbox Organization")
                .returning(OrganizationDB.id)
            )
        ).scalar_one()
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
        user_email_id = (
            await session.execute(
                insert(UserEmailDB)
                .values(
                    user_id=user.id,
                    email="outbox@example.com",
                    normalized_email="outbox@example.com",
                    status=UserEmailStatus.CURRENT,
                )
                .returning(UserEmailDB.id)
            )
        ).scalar_one()
        session.add(
            OrganizationMembershipDB(
                user_id=user.id,
                organization_id=organization_id,
            )
        )
        event = AccountVerificationRequested(
            user_public_id=PublicId(user.public_id),
            user_email_id=user_email_id,
        )
        correlation_token = correlation_id_context.set(OUTBOX_CORRELATION_ID)
        try:
            await OutboxEventPublisher(session).publish(event)
        finally:
            correlation_id_context.reset(correlation_token)
        await session.commit()
        return event.event_id


@pytest.mark.asyncio
async def test_dispatcher_creates_one_retry_stable_token(app: FastAPI) -> None:
    """Retry delivery with the same event and token without storing it raw."""
    event_id = await _seed_verification_event(app)
    settings = _email_enabled_settings(app)

    with patch(
        "app.events.dispatcher._mail_service",
        return_value=_SuccessfulMailService(),
    ):
        assert (
            await dispatch_pending_once(app.state.core_session_factory, settings) == 1
        )

    async with app.state.core_session_factory() as session:
        token_row = await session.scalar(
            select(UserAuthTokenDB).where(UserAuthTokenDB.source_event_id == event_id)
        )
        outbox_row = await session.scalar(
            select(AuthEventOutboxDB).where(AuthEventOutboxDB.event_id == event_id)
        )
        assert token_row is not None
        assert outbox_row is not None
        first_token = await AuthTokenService(
            db_session=session,
            settings=app.state.settings.auth.tokens,
        ).issue_token_for_event(
            event_id=event_id,
            event_occurred_at=outbox_row.occurred_at,
            user_email_id=token_row.user_email_id,
            purpose=AuthTokenPurpose.verify_email,
        )
        await session.execute(
            update(AuthEventOutboxDB)
            .where(AuthEventOutboxDB.id == outbox_row.id)
            .values(processed_at=None, available_at=outbox_row.occurred_at)
        )
        await session.commit()

    with patch(
        "app.events.dispatcher._mail_service",
        return_value=_SuccessfulMailService(),
    ):
        assert (
            await dispatch_pending_once(app.state.core_session_factory, settings) == 1
        )

    async with app.state.core_session_factory() as session:
        token_count = await session.scalar(
            select(func.count())
            .select_from(UserAuthTokenDB)
            .where(UserAuthTokenDB.source_event_id == event_id)
        )
        token_row = await session.scalar(
            select(UserAuthTokenDB).where(UserAuthTokenDB.source_event_id == event_id)
        )
        assert token_row is not None
        second_token = await AuthTokenService(
            db_session=session,
            settings=app.state.settings.auth.tokens,
        ).issue_token_for_event(
            event_id=event_id,
            event_occurred_at=outbox_row.occurred_at,
            user_email_id=token_row.user_email_id,
            purpose=AuthTokenPurpose.verify_email,
        )

    assert token_count == 1
    assert second_token == first_token
    assert first_token not in str(outbox_row.payload)


@pytest.mark.asyncio
async def test_claim_is_exclusive_and_expired_lease_is_recoverable(
    app: FastAPI,
) -> None:
    """Only one worker owns a live lease, while a crashed lease is reclaimed."""
    event_id = await _seed_verification_event(app)
    now = datetime.now(UTC)
    async with app.state.core_session_factory() as first_session:
        first = await _claim_pending(
            first_session,
            worker_id="worker-one",
            now=now,
            settings=app.state.settings.events,
        )
    async with app.state.core_session_factory() as second_session:
        second = await _claim_pending(
            second_session,
            worker_id="worker-two",
            now=now,
            settings=app.state.settings.events,
        )
        await second_session.execute(
            update(AuthEventOutboxDB)
            .where(AuthEventOutboxDB.event_id == event_id)
            .values(
                claimed_at=now
                - timedelta(seconds=app.state.settings.events.lease_seconds + 1)
            )
        )
        await second_session.commit()
    async with app.state.core_session_factory() as recovered_session:
        recovered = await _claim_pending(
            recovered_session,
            worker_id="worker-two",
            now=now,
            settings=app.state.settings.events,
        )

    assert len(first) == 1
    assert second == []
    assert recovered == first


class _FailingMailService:
    """Mail transport fake that makes dispatcher retries observable."""

    async def send_template(self, _message: object) -> None:
        """Fail every attempted delivery."""
        message = "smtp unavailable"
        raise RuntimeError(message)


class _SuccessfulMailService:
    """Mail fake accepting delivery without external infrastructure."""

    async def send_template(self, _message: object) -> None:
        """Accept the message."""


class _CorrelationCapturingMailService:
    """Mail fake recording the context restored by the dispatcher."""

    correlation_id: str | None = None

    async def send_template(self, _message: object) -> None:
        """Observe causal request context during the external side effect."""
        self.correlation_id = correlation_id_context.get()


@pytest.mark.asyncio
async def test_dispatcher_restores_and_resets_event_correlation_id(
    app: FastAPI,
) -> None:
    """Correlate delivery without leaking one event's context to the next task."""
    await _seed_verification_event(app)
    mail_service = _CorrelationCapturingMailService()

    with patch("app.events.dispatcher._mail_service", return_value=mail_service):
        processed = await dispatch_pending_once(
            app.state.core_session_factory,
            _email_enabled_settings(app),
        )

    assert processed == 1
    assert mail_service.correlation_id == OUTBOX_CORRELATION_ID
    assert correlation_id_context.get() is None


def _email_enabled_settings(app: FastAPI) -> Settings:
    """Enable delivery while preserving the fixture's other settings."""
    return app.state.settings.model_copy(
        update={"mail": app.state.settings.mail.model_copy(update={"enabled": True})}
    )


@pytest.mark.asyncio
async def test_dispatch_failure_records_error_and_backoff(
    app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Release a failed claim with capped exponential retry metadata."""
    event_id = await _seed_verification_event(app)
    monkeypatch.setattr(
        "app.events.dispatcher._mail_service",
        lambda _settings: _FailingMailService(),
    )

    processed = await dispatch_pending_once(
        app.state.core_session_factory, _email_enabled_settings(app)
    )

    async with app.state.core_session_factory() as session:
        row = await session.scalar(
            select(AuthEventOutboxDB).where(AuthEventOutboxDB.event_id == event_id)
        )
    assert processed == 0
    assert row is not None
    assert row.attempt_count == 1
    assert row.claimed_at is None
    assert row.claimed_by is None
    assert row.last_error == "smtp unavailable"
    assert row.available_at > row.occurred_at


@pytest.mark.asyncio
async def test_missing_rotation_key_keeps_delivery_pending(app: FastAPI) -> None:
    """Retry instead of delivering a link derived with an unrelated new key."""
    event_id = await _seed_verification_event(app)
    settings = _email_enabled_settings(app)
    with patch(
        "app.events.dispatcher._mail_service",
        return_value=_SuccessfulMailService(),
    ):
        assert (
            await dispatch_pending_once(app.state.core_session_factory, settings) == 1
        )
    async with app.state.core_session_factory() as session:
        await session.execute(
            update(AuthEventOutboxDB)
            .where(AuthEventOutboxDB.event_id == event_id)
            .values(processed_at=None, available_at=datetime.now(UTC))
        )
        await session.commit()
    rotated_tokens = settings.auth.tokens.model_copy(
        update={
            "derivation_key_id": "new",
            "derivation_secret": SecretStr("new-derivation-secret-at-least-32"),
        }
    )
    rotated_settings = settings.model_copy(
        update={"auth": settings.auth.model_copy(update={"tokens": rotated_tokens})}
    )

    processed = await dispatch_pending_once(
        app.state.core_session_factory,
        rotated_settings,
    )

    async with app.state.core_session_factory() as session:
        row = await session.scalar(
            select(AuthEventOutboxDB).where(AuthEventOutboxDB.event_id == event_id)
        )
    assert processed == 0
    assert row is not None
    assert row.processed_at is None
    assert row.attempt_count == 1
    assert row.last_error is not None
    assert "'default' is unavailable" in row.last_error


@pytest.mark.asyncio
async def test_disabled_email_discards_without_creating_token(app: FastAPI) -> None:
    """Do not invalidate auth tokens for a transport that cannot deliver."""
    event_id = await _seed_verification_event(app)

    processed = await dispatch_pending_once(
        app.state.core_session_factory, app.state.settings
    )

    async with app.state.core_session_factory() as session:
        row = await session.scalar(
            select(AuthEventOutboxDB).where(AuthEventOutboxDB.event_id == event_id)
        )
        token_count = await session.scalar(
            select(func.count()).select_from(UserAuthTokenDB)
        )
    assert processed == 1
    assert row is not None
    assert row.processing_result == "discarded_email_disabled"
    assert token_count == 0


@pytest.mark.asyncio
async def test_dispatch_stops_before_claiming_more_work(app: FastAPI) -> None:
    """Honor shutdown before claiming another event from the batch."""
    event_id = await _seed_verification_event(app)
    stop_event = asyncio.Event()
    stop_event.set()

    processed = await dispatch_pending_once(
        app.state.core_session_factory,
        app.state.settings,
        stop_event=stop_event,
    )

    async with app.state.core_session_factory() as session:
        row = await session.scalar(
            select(AuthEventOutboxDB).where(AuthEventOutboxDB.event_id == event_id)
        )
    assert processed == 0
    assert row is not None
    assert row.claimed_at is None


@pytest.mark.asyncio
async def test_processed_event_cleanup_is_bounded(app: FastAPI) -> None:
    """Delete only one configured retention batch per cleanup transaction."""
    async with app.state.core_session_factory() as session:
        publisher = OutboxEventPublisher(session)
        await publisher.publish(
            AccountVerificationRequested(
                user_public_id=PublicId(1),
                user_email_id=1,
            )
        )
        await publisher.publish(
            AccountVerificationRequested(
                user_public_id=PublicId(2),
                user_email_id=2,
            )
        )
        await session.execute(
            update(AuthEventOutboxDB).values(
                processed_at=datetime.now(UTC) - timedelta(days=30)
            )
        )
        await session.commit()
    event_settings = app.state.settings.events.model_copy(
        update={"cleanup_batch_size": 1}
    )
    settings = app.state.settings.model_copy(update={"events": event_settings})

    deleted = await cleanup_processed_events(
        app.state.core_session_factory,
        settings,
    )

    async with app.state.core_session_factory() as session:
        remaining = await session.scalar(
            select(func.count()).select_from(AuthEventOutboxDB)
        )
    assert deleted == 1
    assert remaining == 1

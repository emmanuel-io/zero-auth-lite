"""Integration tests for durable authentication-event dispatch."""

import asyncio
from datetime import datetime, timedelta, UTC
from typing import cast
from unittest.mock import patch

import pytest
from app.db.models.notification_outbox import NotificationOutboxDB
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.db.models.workflow_token import UserWorkflowTokenDB
from app.identity.users.enums import UserEmailStatus
from app.mail.errors import MailTemplateError
from app.notifications.builder import UnsupportedNotificationEventError
from app.notifications.dispatcher import (
    _process_claimed,
    cleanup_processed_events,
    dispatch_pending_once,
)
from app.notifications.events import AccountVerificationRequested
from app.notifications.lease import _record_permanent_failure
from app.notifications.publisher import NotificationOutboxPublisher
from app.notifications.specs import OutboxProcessingResult
from app.settings.root import Settings
from app.workflow_tokens.enums import WorkflowTokenPurpose
from app.workflow_tokens.service import WorkflowTokenService
from asgi_correlation_id.context import correlation_id as correlation_id_context
from fastapi import FastAPI
from pydantic import SecretStr
from sqlalchemy import func, insert, select, text, update

from tests.identifiers import PublicId


pytestmark = pytest.mark.integration
OUTBOX_CORRELATION_ID = "a" * 32


async def _seed_verification_event(
    app: FastAPI,
    *,
    email: str = "outbox@example.com",
    first_name: str = "",
) -> str:
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
                    first_name=first_name,
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
                    email=email,
                    normalized_email=email,
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
            await NotificationOutboxPublisher(session).publish(event)
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
        "app.notifications.dispatcher.build_mail_service",
        return_value=_SuccessfulMailService(),
    ):
        assert (
            await dispatch_pending_once(app.state.core_session_factory, settings) == 1
        )

    async with app.state.core_session_factory() as session:
        token_row = await session.scalar(
            select(UserWorkflowTokenDB).where(
                UserWorkflowTokenDB.source_event_id == event_id
            )
        )
        outbox_row = await session.scalar(
            select(NotificationOutboxDB).where(
                NotificationOutboxDB.event_id == event_id
            )
        )
        assert token_row is not None
        assert outbox_row is not None
        first_token = await WorkflowTokenService(
            db_session=session,
            settings=app.state.settings.identity_workflow.workflow_tokens,
        ).issue_token_for_event(
            event_id=event_id,
            event_occurred_at=outbox_row.occurred_at,
            user_email_id=token_row.user_email_id,
            purpose=WorkflowTokenPurpose.VERIFY_EMAIL,
        )
        await session.execute(
            update(NotificationOutboxDB)
            .where(NotificationOutboxDB.id == outbox_row.id)
            .values(
                processed_at=None,
                processing_result=None,
                available_at=outbox_row.occurred_at,
            )
        )
        await session.commit()

    with patch(
        "app.notifications.dispatcher.build_mail_service",
        return_value=_SuccessfulMailService(),
    ):
        assert (
            await dispatch_pending_once(app.state.core_session_factory, settings) == 1
        )

    async with app.state.core_session_factory() as session:
        token_count = await session.scalar(
            select(func.count())
            .select_from(UserWorkflowTokenDB)
            .where(UserWorkflowTokenDB.source_event_id == event_id)
        )
        token_row = await session.scalar(
            select(UserWorkflowTokenDB).where(
                UserWorkflowTokenDB.source_event_id == event_id
            )
        )
        assert token_row is not None
        second_token = await WorkflowTokenService(
            db_session=session,
            settings=app.state.settings.identity_workflow.workflow_tokens,
        ).issue_token_for_event(
            event_id=event_id,
            event_occurred_at=outbox_row.occurred_at,
            user_email_id=token_row.user_email_id,
            purpose=WorkflowTokenPurpose.VERIFY_EMAIL,
        )

    assert token_count == 1
    assert second_token == first_token
    assert first_token is not None
    assert first_token not in str(outbox_row.payload)


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


class _ClaimStealingMailService:
    """Mail fake that simulates lease reassignment during delivery."""

    def __init__(self, app: FastAPI) -> None:
        """Keep the session factory used to replace the dispatcher's claim."""
        self.session_factory = app.state.core_session_factory

    async def send_template(self, _message: object) -> None:
        """Transfer every pending claim before delivery returns."""
        async with self.session_factory() as session:
            await session.execute(
                update(NotificationOutboxDB)
                .where(NotificationOutboxDB.processed_at.is_(None))
                .values(claimed_by="successor-worker", claimed_at=datetime.now(UTC))
            )
            await session.commit()


@pytest.mark.asyncio
async def test_dispatcher_does_not_finalize_a_reassigned_lease(app: FastAPI) -> None:
    """Do not count delivery when another worker owns finalization."""
    event_id = await _seed_verification_event(app)

    processed = await dispatch_pending_once(
        app.state.core_session_factory,
        _email_enabled_settings(app),
        worker_id="original-worker",
        mail_service=_ClaimStealingMailService(app),  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
    )

    async with app.state.core_session_factory() as session:
        row = await session.scalar(
            select(NotificationOutboxDB).where(
                NotificationOutboxDB.event_id == event_id
            )
        )
    assert processed == 0
    assert row is not None
    assert row.processed_at is None
    assert row.claimed_by == "successor-worker"


@pytest.mark.asyncio
async def test_heartbeat_failure_does_not_hide_successful_delivery(
    app: FastAPI,
) -> None:
    """Finalize a delivered event even when its supporting heartbeat fails."""
    event_id = await _seed_verification_event(app)

    with patch(
        "app.notifications.dispatcher._renew_lease",
        side_effect=RuntimeError("heartbeat unavailable"),
    ):
        processed = await dispatch_pending_once(
            app.state.core_session_factory,
            _email_enabled_settings(app),
            mail_service=_SuccessfulMailService(),  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        )

    async with app.state.core_session_factory() as session:
        row = await session.scalar(
            select(NotificationOutboxDB).where(
                NotificationOutboxDB.event_id == event_id
            )
        )
    assert processed == 1
    assert row is not None
    assert row.processed_at is not None
    assert row.processing_result == "delivered"


@pytest.mark.asyncio
async def test_heartbeat_failure_does_not_skip_delivery_reschedule(
    app: FastAPI,
) -> None:
    """Record delivery failure even when lease renewal also fails."""
    event_id = await _seed_verification_event(app)

    with patch(
        "app.notifications.dispatcher._renew_lease",
        side_effect=RuntimeError("heartbeat unavailable"),
    ):
        processed = await dispatch_pending_once(
            app.state.core_session_factory,
            _email_enabled_settings(app),
            mail_service=_FailingMailService(),  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        )

    async with app.state.core_session_factory() as session:
        row = await session.scalar(
            select(NotificationOutboxDB).where(
                NotificationOutboxDB.event_id == event_id
            )
        )
    assert processed == 0
    assert row is not None
    assert row.processed_at is None
    assert row.attempt_count == 1
    assert row.claimed_at is None
    assert row.claimed_by is None
    assert row.last_error == "smtp unavailable"


@pytest.mark.asyncio
async def test_processing_stops_when_the_claim_is_already_lost(app: FastAPI) -> None:
    """Return an explicit unsuccessful result before building a message."""
    event_id = await _seed_verification_event(app)
    async with app.state.core_session_factory() as session:
        row = await session.scalar(
            select(NotificationOutboxDB).where(
                NotificationOutboxDB.event_id == event_id
            )
        )
        assert row is not None
        row.claimed_by = "successor-worker"
        row.claimed_at = datetime.now(UTC)
        await session.commit()

    finalized = await _process_claimed(
        app.state.core_session_factory,
        event_db_id=row.id,
        worker_id="original-worker",
        settings=_email_enabled_settings(app),
        mail_service=_SuccessfulMailService(),  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
    )

    assert finalized is False

    recorded = await _record_permanent_failure(
        app.state.core_session_factory,
        event_db_id=row.id,
        worker_id="original-worker",
        error=ValueError("invalid event"),
    )
    assert recorded is False


@pytest.mark.asyncio
async def test_dispatcher_reuses_mail_service_for_one_batch(app: FastAPI) -> None:
    """Build the mail delivery boundary once for all events in one batch."""
    emails = ("first@example.com", "second@example.com")
    for email in emails:
        await _seed_verification_event(app, email=email)
    mail_service = _SuccessfulMailService()

    with patch(
        "app.notifications.dispatcher.build_mail_service",
        return_value=mail_service,
    ) as build_service:
        processed = await dispatch_pending_once(
            app.state.core_session_factory,
            _email_enabled_settings(app),
        )

    assert processed == len(emails)
    build_service.assert_called_once()


class _InvalidTemplateMailService:
    """Mail fake exposing a permanent template failure."""

    async def send_template(self, _message: object) -> None:
        """Reject the message because its template cannot be rendered."""
        raise MailTemplateError


class _UnhandledNotificationService:
    """Notification fake exposing a missing event handler."""

    async def build(self, _event: object) -> None:
        """Reject the event because no message builder handles it."""
        message = "Unsupported notification event type: auth.test"
        raise UnsupportedNotificationEventError(message)


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

    with patch(
        "app.notifications.dispatcher.build_mail_service", return_value=mail_service
    ):
        processed = await dispatch_pending_once(
            app.state.core_session_factory,
            _email_enabled_settings(app),
        )

    assert processed == 1
    assert mail_service.correlation_id == OUTBOX_CORRELATION_ID
    assert correlation_id_context.get() is None


def _email_enabled_settings(app: FastAPI) -> Settings:
    """Enable delivery while preserving the fixture's other settings."""
    return cast(
        "Settings",
        app.state.settings.model_copy(
            update={
                "mail": app.state.settings.mail.model_copy(update={"enabled": True})
            }
        ),
    )


@pytest.mark.asyncio
async def test_dispatch_failure_records_error_and_backoff(
    app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Release a failed claim with capped exponential retry metadata."""
    event_id = await _seed_verification_event(app)
    monkeypatch.setattr(
        "app.notifications.dispatcher.build_mail_service",
        lambda _settings: _FailingMailService(),
    )

    processed = await dispatch_pending_once(
        app.state.core_session_factory, _email_enabled_settings(app)
    )

    async with app.state.core_session_factory() as session:
        row = await session.scalar(
            select(NotificationOutboxDB).where(
                NotificationOutboxDB.event_id == event_id
            )
        )
    assert processed == 0
    assert row is not None
    assert row.attempt_count == 1
    assert row.claimed_at is None
    assert row.claimed_by is None
    assert row.last_error == "smtp unavailable"
    assert row.available_at > row.occurred_at


@pytest.mark.asyncio
async def test_invalid_event_payload_is_recorded_as_a_permanent_failure(
    app: FastAPI,
) -> None:
    """Finalize corrupt persisted data instead of retrying it forever."""
    event_id = await _seed_verification_event(app)
    async with app.state.core_session_factory() as session:
        await session.execute(
            update(NotificationOutboxDB)
            .where(NotificationOutboxDB.event_id == event_id)
            .values(payload={})
        )
        await session.commit()

    processed = await dispatch_pending_once(
        app.state.core_session_factory, _email_enabled_settings(app)
    )

    async with app.state.core_session_factory() as session:
        row = await session.scalar(
            select(NotificationOutboxDB).where(
                NotificationOutboxDB.event_id == event_id
            )
        )
    assert processed == 1
    assert row is not None
    assert row.processed_at is not None
    assert row.processing_result == "failed_permanent"
    assert row.attempt_count == 0
    assert row.claimed_at is None
    assert row.claimed_by is None
    assert row.last_error == (
        "Invalid persisted payload for outbox event type: "
        "auth.account_verification_requested"
    )


@pytest.mark.asyncio
async def test_template_error_is_recorded_as_a_permanent_failure(app: FastAPI) -> None:
    """Do not retry a template that cannot render the same message."""
    event_id = await _seed_verification_event(app)

    with patch(
        "app.notifications.dispatcher.build_mail_service",
        return_value=_InvalidTemplateMailService(),
    ):
        processed = await dispatch_pending_once(
            app.state.core_session_factory, _email_enabled_settings(app)
        )

    async with app.state.core_session_factory() as session:
        row = await session.scalar(
            select(NotificationOutboxDB).where(
                NotificationOutboxDB.event_id == event_id
            )
        )
    assert processed == 1
    assert row is not None
    assert row.processing_result == "failed_permanent"
    assert row.processed_at is not None
    assert row.last_error == (
        "[MAIL_TEMPLATE_ERROR] Mail template could not be rendered."
    )


@pytest.mark.asyncio
async def test_unhandled_event_is_recorded_as_a_permanent_failure(
    app: FastAPI,
) -> None:
    """Do not report an absent notification handler as a stale target."""
    event_id = await _seed_verification_event(app)

    with patch(
        "app.notifications.dispatcher._notification_builder",
        return_value=_UnhandledNotificationService(),
    ):
        processed = await dispatch_pending_once(
            app.state.core_session_factory,
            _email_enabled_settings(app),
            mail_service=_SuccessfulMailService(),  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        )

    async with app.state.core_session_factory() as session:
        row = await session.scalar(
            select(NotificationOutboxDB).where(
                NotificationOutboxDB.event_id == event_id
            )
        )
    assert processed == 1
    assert row is not None
    assert row.processing_result == "failed_permanent"
    assert row.processed_at is not None
    assert row.last_error == "Unsupported notification event type: auth.test"


@pytest.mark.asyncio
async def test_invalid_mail_header_is_recorded_as_a_permanent_failure(
    app: FastAPI,
) -> None:
    """Keep corrupt legacy identity data from causing infinite mail retries."""
    event_id = await _seed_verification_event(app)
    async with app.state.core_session_factory() as session:
        await session.execute(text("PRAGMA ignore_check_constraints = ON"))
        await session.execute(update(UserDB).values(first_name="Invalid\nName"))
        await session.commit()
        await session.execute(text("PRAGMA ignore_check_constraints = OFF"))
        await session.commit()

    processed = await dispatch_pending_once(
        app.state.core_session_factory,
        _email_enabled_settings(app),
    )

    async with app.state.core_session_factory() as session:
        row = await session.scalar(
            select(NotificationOutboxDB).where(
                NotificationOutboxDB.event_id == event_id
            )
        )
    assert processed == 1
    assert row is not None
    assert row.processing_result == "failed_permanent"
    assert row.last_error == (
        "Invalid notification message for outbox event type: "
        "auth.account_verification_requested"
    )


@pytest.mark.asyncio
async def test_missing_rotation_key_keeps_delivery_pending(app: FastAPI) -> None:
    """Retry instead of delivering a link derived with an unrelated new key."""
    event_id = await _seed_verification_event(app)
    settings = _email_enabled_settings(app)
    with patch(
        "app.notifications.dispatcher.build_mail_service",
        return_value=_SuccessfulMailService(),
    ):
        assert (
            await dispatch_pending_once(app.state.core_session_factory, settings) == 1
        )
    async with app.state.core_session_factory() as session:
        await session.execute(
            update(NotificationOutboxDB)
            .where(NotificationOutboxDB.event_id == event_id)
            .values(
                processed_at=None,
                processing_result=None,
                available_at=datetime.now(UTC),
            )
        )
        await session.commit()
    rotated_tokens = settings.identity_workflow.workflow_tokens.model_copy(
        update={
            "derivation_key_id": "new",
            "derivation_secret": SecretStr("new-derivation-secret-at-least-32"),
        }
    )
    rotated_settings = settings.model_copy(
        update={
            "identity_workflow": settings.identity_workflow.model_copy(
                update={"workflow_tokens": rotated_tokens}
            )
        }
    )

    processed = await dispatch_pending_once(
        app.state.core_session_factory,
        rotated_settings,
    )

    async with app.state.core_session_factory() as session:
        row = await session.scalar(
            select(NotificationOutboxDB).where(
                NotificationOutboxDB.event_id == event_id
            )
        )
    assert processed == 0
    assert row is not None
    assert row.processed_at is None
    assert row.attempt_count == 1
    assert row.last_error is not None
    assert "'default' is unavailable" in row.last_error


@pytest.mark.asyncio
async def test_disabled_email_discards_without_creating_token(app: FastAPI) -> None:
    """Do not invalidate workflow tokens for a transport that cannot deliver."""
    event_id = await _seed_verification_event(app)

    processed = await dispatch_pending_once(
        app.state.core_session_factory, app.state.settings
    )

    async with app.state.core_session_factory() as session:
        row = await session.scalar(
            select(NotificationOutboxDB).where(
                NotificationOutboxDB.event_id == event_id
            )
        )
        token_count = await session.scalar(
            select(func.count()).select_from(UserWorkflowTokenDB)
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
            select(NotificationOutboxDB).where(
                NotificationOutboxDB.event_id == event_id
            )
        )
    assert processed == 0
    assert row is not None
    assert row.claimed_at is None


@pytest.mark.asyncio
async def test_processed_event_cleanup_is_bounded(app: FastAPI) -> None:
    """Delete only one configured retention batch per cleanup transaction."""
    async with app.state.core_session_factory() as session:
        publisher = NotificationOutboxPublisher(session)
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
            update(NotificationOutboxDB).values(
                processed_at=datetime.now(UTC) - timedelta(days=30),
                processing_result=OutboxProcessingResult.DELIVERED,
            )
        )
        await session.commit()
    notification_settings = app.state.settings.notification_outbox.model_copy(
        update={"cleanup_batch_size": 1}
    )
    settings = app.state.settings.model_copy(
        update={"notification_outbox": notification_settings}
    )

    deleted = await cleanup_processed_events(
        app.state.core_session_factory,
        settings,
    )

    async with app.state.core_session_factory() as session:
        remaining = await session.scalar(
            select(func.count()).select_from(NotificationOutboxDB)
        )
    assert deleted == 1
    assert remaining == 1

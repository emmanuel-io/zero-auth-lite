"""Lease-based dispatcher for durable authentication notifications."""

import asyncio
from datetime import datetime, timedelta, UTC
from logging import getLogger
from uuid import uuid4

from asgi_correlation_id.context import correlation_id as correlation_id_context
from pydantic import ValidationError
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from app.db.models.notification_outbox import NotificationOutboxDB
from app.mail.errors import MailTemplateError
from app.mail.service import build_mail_service, MailService
from app.notifications.builder import (
    AuthNotificationBuilder,
    UnsupportedNotificationEventError,
)
from app.notifications.event import NotificationEvent
from app.notifications.events import NOTIFICATION_EVENT_REGISTRY
from app.notifications.lease import (
    _claim_pending,
    _claimed_correlation_id,
    _finalize_claim,
    _record_permanent_failure,
    _renew_lease,
    _reschedule,
)
from app.notifications.specs import OutboxProcessingResult
from app.settings.root import Settings
from app.workflow_tokens.service import WorkflowTokenService


logger = getLogger(__name__)


class PermanentOutboxError(Exception):
    """Failure that cannot clear by retrying the unchanged outbox event."""


def _event_from_row(row: NotificationOutboxDB) -> NotificationEvent:
    """Validate one persisted outbox payload against its event type."""
    event_class = NOTIFICATION_EVENT_REGISTRY.get(row.event_type)
    if event_class is None:
        msg = f"Unsupported outbox event type: {row.event_type}"
        raise PermanentOutboxError(msg)
    try:
        return event_class.model_validate(row.payload)
    except ValueError as exc:
        msg = f"Invalid persisted payload for outbox event type: {row.event_type}"
        raise PermanentOutboxError(msg) from exc


def _notification_builder(
    session: AsyncSession, settings: Settings
) -> AuthNotificationBuilder:
    """Build the token-aware notification builder for one DB transaction."""
    token_service = WorkflowTokenService(
        db_session=session,
        settings=settings.identity_workflow.workflow_tokens,
    )
    return AuthNotificationBuilder(
        db_session=session,
        workflow_token_service=token_service,
        workflow_urls=settings.ui.urls,
    )


async def _stop_lease_renewal(
    lease_task: asyncio.Task[None], lease_stop: asyncio.Event, *, event_db_id: int
) -> None:
    """Stop supporting lease work without masking the delivery outcome."""
    lease_stop.set()
    try:
        await lease_task
    except Exception:
        logger.exception(
            "Outbox event lease heartbeat failed event_id=%s",
            event_db_id,
        )


async def _process_claimed(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_db_id: int,
    worker_id: str,
    settings: Settings,
    mail_service: MailService | None,
) -> bool:
    """Render, optionally deliver, then finalize one already-claimed event."""
    async with session_factory() as session:
        row = await session.scalar(
            select(NotificationOutboxDB)
            .where(NotificationOutboxDB.id == event_db_id)
            .where(NotificationOutboxDB.claimed_by == worker_id)
            .where(NotificationOutboxDB.processed_at.is_(None))
        )
        if row is None:
            return False
        event = _event_from_row(row)
        if not settings.mail.enabled:
            # Do not create or invalidate workflow tokens when delivery is disabled.
            message = None
            processing_result = OutboxProcessingResult.DISCARDED_EMAIL_DISABLED
        else:
            try:
                message = await _notification_builder(session, settings).build(event)
            except ValidationError as exc:
                msg = (
                    "Invalid notification message for outbox event type: "
                    f"{event.event_type}"
                )
                raise PermanentOutboxError(msg) from exc
            await session.commit()
            processing_result = (
                OutboxProcessingResult.DELIVERED
                if message is not None
                else OutboxProcessingResult.DISCARDED_TARGET_UNAVAILABLE
            )

    if message is not None:
        if mail_service is None:
            msg = "Mail delivery is enabled without a configured service."
            raise RuntimeError(msg)
        await mail_service.send_template(message)

    return await _finalize_claim(
        session_factory,
        event_db_id=event_db_id,
        worker_id=worker_id,
        processing_result=processing_result,
    )


async def dispatch_pending_once(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    *,
    worker_id: str | None = None,
    stop_event: asyncio.Event | None = None,
    mail_service: MailService | None = None,
) -> int:
    """Claim and process up to one batch, one leased event at a time."""
    resolved_worker_id = worker_id or uuid4().hex
    processed = 0
    for _ in range(settings.notification_outbox.batch_size):
        if stop_event is not None and stop_event.is_set():
            break
        async with session_factory() as session:
            event_ids = await _claim_pending(
                session,
                worker_id=resolved_worker_id,
                now=datetime.now(UTC),
                settings=settings.notification_outbox,
                limit=1,
            )
        if not event_ids:
            break
        if settings.mail.enabled and mail_service is None:
            mail_service = await asyncio.to_thread(build_mail_service, settings.mail)
        event_db_id = event_ids[0]
        event_correlation_id = await _claimed_correlation_id(
            session_factory,
            event_db_id=event_db_id,
            worker_id=resolved_worker_id,
        )
        correlation_token = correlation_id_context.set(event_correlation_id)
        try:
            lease_stop = asyncio.Event()
            lease_task = asyncio.create_task(
                _renew_lease(
                    session_factory,
                    event_db_id=event_db_id,
                    worker_id=resolved_worker_id,
                    settings=settings.notification_outbox,
                    stop_event=lease_stop,
                )
            )
            delivery_error: Exception | None = None
            finalized = False
            try:
                finalized = await _process_claimed(
                    session_factory,
                    event_db_id=event_db_id,
                    worker_id=resolved_worker_id,
                    settings=settings,
                    mail_service=mail_service,
                )
            except Exception as exc:  # noqa: BLE001
                delivery_error = exc
            finally:
                await _stop_lease_renewal(
                    lease_task,
                    lease_stop,
                    event_db_id=event_db_id,
                )
            if delivery_error is not None:
                logger.error(
                    "Outbox event delivery failed event_id=%s",
                    event_db_id,
                    exc_info=delivery_error,
                )
                if isinstance(
                    delivery_error,
                    (
                        PermanentOutboxError,
                        MailTemplateError,
                        UnsupportedNotificationEventError,
                    ),
                ):
                    finalized = await _record_permanent_failure(
                        session_factory,
                        event_db_id=event_db_id,
                        worker_id=resolved_worker_id,
                        error=delivery_error,
                    )
                else:
                    await _reschedule(
                        session_factory,
                        event_db_id=event_db_id,
                        worker_id=resolved_worker_id,
                        error=delivery_error,
                        settings=settings.notification_outbox,
                    )
            if finalized:
                logger.info("Outbox event processed event_id=%s", event_db_id)
                processed += 1
            elif delivery_error is None or isinstance(
                delivery_error,
                (
                    PermanentOutboxError,
                    MailTemplateError,
                    UnsupportedNotificationEventError,
                ),
            ):
                logger.warning(
                    "Outbox event lease lost before finalization event_id=%s",
                    event_db_id,
                )
        finally:
            correlation_id_context.reset(correlation_token)
    return processed


async def cleanup_processed_events(
    session_factory: async_sessionmaker[AsyncSession], settings: Settings
) -> int:
    """Delete terminal events older than the configured retention period."""
    cutoff = datetime.now(UTC) - timedelta(
        seconds=settings.notification_outbox.retention_seconds
    )
    async with session_factory() as session:
        expired_ids = (
            select(NotificationOutboxDB.id)
            .where(NotificationOutboxDB.processed_at <= cutoff)
            .order_by(NotificationOutboxDB.id)
            .limit(settings.notification_outbox.cleanup_batch_size)
        )
        result = await session.execute(
            delete(NotificationOutboxDB).where(NotificationOutboxDB.id.in_(expired_ids))
        )
        await session.commit()
        return int(getattr(result, "rowcount", 0) or 0)


async def run_outbox_dispatcher(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    stop_event: asyncio.Event,
    *,
    mail_service: MailService | None,
) -> None:
    """Poll the outbox until worker shutdown is requested."""
    worker_id = uuid4().hex
    cleanup_after = 0.0
    while not stop_event.is_set():
        try:
            await dispatch_pending_once(
                session_factory,
                settings,
                worker_id=worker_id,
                stop_event=stop_event,
                mail_service=mail_service,
            )
            now = asyncio.get_running_loop().time()
            if now >= cleanup_after:
                await cleanup_processed_events(session_factory, settings)
                cleanup_after = (
                    now + settings.notification_outbox.cleanup_interval_seconds
                )
        except Exception:
            # A database outage must not permanently kill the worker.
            logger.exception("Outbox polling failed worker_id=%s", worker_id)
        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=settings.notification_outbox.poll_interval_seconds,
            )
        except TimeoutError:
            continue

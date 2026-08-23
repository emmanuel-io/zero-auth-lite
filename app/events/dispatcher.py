"""Lease-based dispatcher for durable authentication notifications."""

import asyncio
from datetime import datetime, timedelta, UTC
from logging import getLogger
from uuid import uuid4

from asgi_correlation_id.context import correlation_id as correlation_id_context
from sqlalchemy import delete, or_, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from app.auth_tokens.service import AuthTokenService
from app.db.models.auth_event import AuthEventOutboxDB
from app.events.base import BaseEvent
from app.events.notifications import AuthNotificationService
from app.events.settings import EventOutboxSettings
from app.events.specs import OutboxProcessingResult
from app.events.types import (
    AccountVerificationRequested,
    EmailChangeRequested,
    InviteCreated,
    PasswordResetRequested,
)
from app.mail.renderer import EmailTemplateRenderer
from app.mail.service import build_mail_provider, MailService
from app.settings.root import Settings


logger = getLogger(__name__)
EVENT_TYPES: dict[str, type[BaseEvent]] = {
    "auth.password_reset_requested": PasswordResetRequested,
    "auth.account_verification_requested": AccountVerificationRequested,
    "auth.email_change_requested": EmailChangeRequested,
    "auth.invite_created": InviteCreated,
}
LAST_ERROR_LENGTH = 2_000


def _event_from_row(row: AuthEventOutboxDB) -> BaseEvent:
    """Validate one persisted outbox payload against its event type."""
    event_class = EVENT_TYPES.get(row.event_type)
    if event_class is None:
        msg = f"Unsupported outbox event type: {row.event_type}"
        raise ValueError(msg)
    return event_class.model_validate(row.payload)


async def _claim_pending(
    session: AsyncSession,
    *,
    worker_id: str,
    now: datetime,
    settings: EventOutboxSettings,
    limit: int | None = None,
) -> list[int]:
    """Claim a bounded batch of deliverable rows with lease-aware CAS updates."""
    lease_expired_at = now - timedelta(seconds=settings.lease_seconds)
    candidate_ids = list(
        await session.scalars(
            select(AuthEventOutboxDB.id)
            .where(AuthEventOutboxDB.processed_at.is_(None))
            .where(AuthEventOutboxDB.available_at <= now)
            .where(
                or_(
                    AuthEventOutboxDB.claimed_at.is_(None),
                    AuthEventOutboxDB.claimed_at <= lease_expired_at,
                )
            )
            .order_by(AuthEventOutboxDB.id)
            .limit(limit or settings.batch_size)
        )
    )
    claimed: list[int] = []
    for event_id in candidate_ids:
        claimed_id = await session.scalar(
            update(AuthEventOutboxDB)
            .where(AuthEventOutboxDB.id == event_id)
            .where(AuthEventOutboxDB.processed_at.is_(None))
            .where(
                or_(
                    AuthEventOutboxDB.claimed_at.is_(None),
                    AuthEventOutboxDB.claimed_at <= lease_expired_at,
                )
            )
            .values(claimed_at=now, claimed_by=worker_id)
            .returning(AuthEventOutboxDB.id)
        )
        if claimed_id is not None:
            claimed.append(claimed_id)
    await session.commit()
    return claimed


def _notification_service(
    session: AsyncSession, settings: Settings
) -> AuthNotificationService:
    """Build the token-aware notification service for one DB transaction."""
    token_service = AuthTokenService(
        db_session=session,
        settings=settings.auth.tokens,
    )
    return AuthNotificationService(
        db_session=session,
        auth_token_service=token_service,
        settings=settings.auth.email,
    )


def _mail_service(settings: Settings) -> MailService:
    """Build the configured mail delivery boundary."""
    return MailService(
        provider=build_mail_provider(settings.mail),
        renderer=EmailTemplateRenderer(settings.mail.template_dir),
        settings=settings.mail,
    )


async def _process_claimed(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_db_id: int,
    worker_id: str,
    settings: Settings,
) -> None:
    """Render, optionally deliver, then finalize one already-claimed event."""
    async with session_factory() as session:
        row = await session.scalar(
            select(AuthEventOutboxDB)
            .where(AuthEventOutboxDB.id == event_db_id)
            .where(AuthEventOutboxDB.claimed_by == worker_id)
            .where(AuthEventOutboxDB.processed_at.is_(None))
        )
        if row is None:
            return
        event = _event_from_row(row)
        if not settings.mail.enabled:
            # Do not create or invalidate workflow tokens when delivery is disabled.
            message = None
            processing_result = OutboxProcessingResult.DISCARDED_EMAIL_DISABLED
        else:
            message = await _notification_service(session, settings).build(event)
            await session.commit()
            processing_result = (
                OutboxProcessingResult.DELIVERED
                if message is not None
                else OutboxProcessingResult.DISCARDED_TARGET_UNAVAILABLE
            )

    if message is not None:
        await _mail_service(settings).send_template(message)

    async with session_factory() as session:
        await session.execute(
            update(AuthEventOutboxDB)
            .where(AuthEventOutboxDB.id == event_db_id)
            .where(AuthEventOutboxDB.claimed_by == worker_id)
            .values(
                processed_at=datetime.now(UTC),
                claimed_at=None,
                claimed_by=None,
                last_error=None,
                processing_result=processing_result,
            )
        )
        await session.commit()


async def _claimed_correlation_id(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_db_id: int,
    worker_id: str,
) -> str | None:
    """Load causal request context only for an event owned by this worker."""
    async with session_factory() as session:
        return await session.scalar(
            select(AuthEventOutboxDB.correlation_id)
            .where(AuthEventOutboxDB.id == event_db_id)
            .where(AuthEventOutboxDB.claimed_by == worker_id)
            .where(AuthEventOutboxDB.processed_at.is_(None))
        )


async def _reschedule(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_db_id: int,
    worker_id: str,
    error: Exception,
    settings: EventOutboxSettings,
) -> None:
    """Release a failed claim and back off its next delivery attempt."""
    async with session_factory() as session:
        row = await session.scalar(
            select(AuthEventOutboxDB)
            .where(AuthEventOutboxDB.id == event_db_id)
            .where(AuthEventOutboxDB.claimed_by == worker_id)
        )
        if row is None:
            return
        attempt_count = row.attempt_count + 1
        delay = min(settings.retry_max_seconds, 2 ** min(attempt_count, 8))
        row.attempt_count = attempt_count
        row.available_at = datetime.now(UTC) + timedelta(seconds=delay)
        row.claimed_at = None
        row.claimed_by = None
        row.last_error = str(error)[:LAST_ERROR_LENGTH]
        await session.commit()


async def _renew_lease(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_db_id: int,
    worker_id: str,
    settings: EventOutboxSettings,
    stop_event: asyncio.Event,
) -> None:
    """Keep a claimed event owned while its external delivery is in flight."""
    interval = max(1.0, settings.lease_seconds / 3)
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except TimeoutError:
            async with session_factory() as session:
                await session.execute(
                    update(AuthEventOutboxDB)
                    .where(AuthEventOutboxDB.id == event_db_id)
                    .where(AuthEventOutboxDB.claimed_by == worker_id)
                    .where(AuthEventOutboxDB.processed_at.is_(None))
                    .values(claimed_at=datetime.now(UTC))
                )
                await session.commit()
        else:
            return


async def dispatch_pending_once(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    *,
    worker_id: str | None = None,
    stop_event: asyncio.Event | None = None,
) -> int:
    """Claim and process up to one batch, one leased event at a time."""
    resolved_worker_id = worker_id or uuid4().hex
    processed = 0
    for _ in range(settings.events.batch_size):
        if stop_event is not None and stop_event.is_set():
            break
        async with session_factory() as session:
            event_ids = await _claim_pending(
                session,
                worker_id=resolved_worker_id,
                now=datetime.now(UTC),
                settings=settings.events,
                limit=1,
            )
        if not event_ids:
            break
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
                    settings=settings.events,
                    stop_event=lease_stop,
                )
            )
            delivery_error: Exception | None = None
            try:
                await _process_claimed(
                    session_factory,
                    event_db_id=event_db_id,
                    worker_id=resolved_worker_id,
                    settings=settings,
                )
            except Exception as exc:  # noqa: BLE001
                delivery_error = exc
            finally:
                lease_stop.set()
                await lease_task
            if delivery_error is not None:
                logger.error(
                    "Outbox event delivery failed event_id=%s",
                    event_db_id,
                    exc_info=delivery_error,
                )
                await _reschedule(
                    session_factory,
                    event_db_id=event_db_id,
                    worker_id=resolved_worker_id,
                    error=delivery_error,
                    settings=settings.events,
                )
            else:
                logger.info("Outbox event processed event_id=%s", event_db_id)
                processed += 1
        finally:
            correlation_id_context.reset(correlation_token)
    return processed


async def cleanup_processed_events(
    session_factory: async_sessionmaker[AsyncSession], settings: Settings
) -> int:
    """Delete delivered events older than the configured retention period."""
    cutoff = datetime.now(UTC) - timedelta(seconds=settings.events.retention_seconds)
    async with session_factory() as session:
        expired_ids = (
            select(AuthEventOutboxDB.id)
            .where(AuthEventOutboxDB.processed_at <= cutoff)
            .order_by(AuthEventOutboxDB.id)
            .limit(settings.events.cleanup_batch_size)
        )
        result = await session.execute(
            delete(AuthEventOutboxDB).where(AuthEventOutboxDB.id.in_(expired_ids))
        )
        await session.commit()
        return int(getattr(result, "rowcount", 0) or 0)


async def run_outbox_dispatcher(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    stop_event: asyncio.Event,
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
            )
            now = asyncio.get_running_loop().time()
            if now >= cleanup_after:
                await cleanup_processed_events(session_factory, settings)
                cleanup_after = now + settings.events.cleanup_interval_seconds
        except Exception:
            # A database outage must not permanently kill the worker.
            logger.exception("Outbox polling failed worker_id=%s", worker_id)
        try:
            await asyncio.wait_for(
                stop_event.wait(), timeout=settings.events.poll_interval_seconds
            )
        except TimeoutError:
            continue

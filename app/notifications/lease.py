"""SQLite-backed lease operations for durable notification delivery."""

import asyncio
from datetime import datetime, timedelta, UTC

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from app.db.models.notification_outbox import NotificationOutboxDB
from app.notifications.settings import NotificationOutboxSettings
from app.notifications.specs import OutboxProcessingResult


LAST_ERROR_LENGTH = 2_000


def _retry_delay_seconds(*, attempt_count: int, maximum: int) -> int:
    """Return exponential retry delay without constructing an oversized integer."""
    if attempt_count >= maximum.bit_length():
        return maximum
    return min(maximum, 1 << attempt_count)


async def _claim_pending(
    session: AsyncSession,
    *,
    worker_id: str,
    now: datetime,
    settings: NotificationOutboxSettings,
    limit: int | None = None,
) -> list[int]:
    """Claim a bounded batch of deliverable rows with lease-aware CAS updates."""
    lease_expired_at = now - timedelta(seconds=settings.lease_seconds)
    candidate_ids = list(
        await session.scalars(
            select(NotificationOutboxDB.id)
            .where(NotificationOutboxDB.processed_at.is_(None))
            .where(NotificationOutboxDB.available_at <= now)
            .where(
                or_(
                    NotificationOutboxDB.claimed_at.is_(None),
                    NotificationOutboxDB.claimed_at <= lease_expired_at,
                )
            )
            .order_by(NotificationOutboxDB.id)
            .limit(limit or settings.batch_size)
        )
    )
    claimed: list[int] = []
    for event_id in candidate_ids:
        claimed_id = await session.scalar(
            update(NotificationOutboxDB)
            .where(NotificationOutboxDB.id == event_id)
            .where(NotificationOutboxDB.processed_at.is_(None))
            .where(
                or_(
                    NotificationOutboxDB.claimed_at.is_(None),
                    NotificationOutboxDB.claimed_at <= lease_expired_at,
                )
            )
            .values(claimed_at=now, claimed_by=worker_id)
            .returning(NotificationOutboxDB.id)
        )
        if claimed_id is not None:
            claimed.append(claimed_id)
    await session.commit()
    return claimed


async def _claimed_correlation_id(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_db_id: int,
    worker_id: str,
) -> str | None:
    """Load causal request context only for an event owned by this worker."""
    async with session_factory() as session:
        return await session.scalar(
            select(NotificationOutboxDB.correlation_id)
            .where(NotificationOutboxDB.id == event_db_id)
            .where(NotificationOutboxDB.claimed_by == worker_id)
            .where(NotificationOutboxDB.processed_at.is_(None))
        )


async def _reschedule(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_db_id: int,
    worker_id: str,
    error: Exception,
    settings: NotificationOutboxSettings,
) -> None:
    """Release a failed claim and back off its next delivery attempt."""
    async with session_factory() as session:
        row = await session.scalar(
            select(NotificationOutboxDB)
            .where(NotificationOutboxDB.id == event_db_id)
            .where(NotificationOutboxDB.claimed_by == worker_id)
        )
        if row is None:
            return
        attempt_count = row.attempt_count + 1
        delay = _retry_delay_seconds(
            attempt_count=attempt_count,
            maximum=settings.retry_max_seconds,
        )
        row.attempt_count = attempt_count
        row.available_at = datetime.now(UTC) + timedelta(seconds=delay)
        row.claimed_at = None
        row.claimed_by = None
        row.last_error = str(error)[:LAST_ERROR_LENGTH]
        await session.commit()


async def _record_permanent_failure(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_db_id: int,
    worker_id: str,
    error: Exception,
) -> bool:
    """Finalize an event whose failure cannot clear on an unchanged retry."""
    return await _finalize_claim(
        session_factory,
        event_db_id=event_db_id,
        worker_id=worker_id,
        processing_result=OutboxProcessingResult.FAILED_PERMANENT,
        last_error=str(error)[:LAST_ERROR_LENGTH],
    )


async def _finalize_claim(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_db_id: int,
    worker_id: str,
    processing_result: OutboxProcessingResult,
    last_error: str | None = None,
) -> bool:
    """Finalize an event only while the caller still owns its live claim."""
    async with session_factory() as session:
        finalized_id = await session.scalar(
            update(NotificationOutboxDB)
            .where(NotificationOutboxDB.id == event_db_id)
            .where(NotificationOutboxDB.claimed_by == worker_id)
            .where(NotificationOutboxDB.processed_at.is_(None))
            .values(
                processed_at=datetime.now(UTC),
                claimed_at=None,
                claimed_by=None,
                last_error=last_error,
                processing_result=processing_result,
            )
            .returning(NotificationOutboxDB.id)
        )
        await session.commit()
        return finalized_id is not None


async def _renew_lease(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    event_db_id: int,
    worker_id: str,
    settings: NotificationOutboxSettings,
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
                    update(NotificationOutboxDB)
                    .where(NotificationOutboxDB.id == event_db_id)
                    .where(NotificationOutboxDB.claimed_by == worker_id)
                    .where(NotificationOutboxDB.processed_at.is_(None))
                    .values(claimed_at=datetime.now(UTC))
                )
                await session.commit()
        else:
            return

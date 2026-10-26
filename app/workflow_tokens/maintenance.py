"""Bounded retention cleanup that preserves notification retry state."""

import asyncio
from datetime import datetime, timedelta, UTC
from typing import cast, TYPE_CHECKING

from sqlalchemy import delete, exists, select

from app.db.models.notification_outbox import NotificationOutboxDB
from app.db.models.workflow_token import UserWorkflowTokenDB


if TYPE_CHECKING:
    from sqlalchemy.engine import CursorResult
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession


async def drain_workflow_token_cleanup(
    session_factory: "async_sessionmaker[AsyncSession]",
    *,
    retention_seconds: int,
    batch_size: int,
    stop_event: asyncio.Event,
) -> int:
    """Remove old terminal tokens unless their email still has pending events.

    Retaining every token for an email with pending delivery preserves both
    same-event retries and the markers that suppress delayed older events.
    """
    cutoff = datetime.now(UTC) - timedelta(seconds=retention_seconds)
    pending_delivery = exists(
        select(NotificationOutboxDB.id).where(
            NotificationOutboxDB.processed_at.is_(None),
            NotificationOutboxDB.payload["user_email_id"].as_integer()
            == UserWorkflowTokenDB.user_email_id,
        )
    )
    terminal_ids = (
        select(UserWorkflowTokenDB.id)
        .where(
            (UserWorkflowTokenDB.expires_at <= cutoff)
            | (UserWorkflowTokenDB.used_at <= cutoff),
            ~pending_delivery,
        )
        .order_by(UserWorkflowTokenDB.id)
        .limit(batch_size)
    )
    statement = delete(UserWorkflowTokenDB).where(
        UserWorkflowTokenDB.id.in_(terminal_ids)
    )
    total_deleted = 0
    while not stop_event.is_set():
        async with session_factory() as session:
            result = cast("CursorResult[object]", await session.execute(statement))
            deleted = int(result.rowcount or 0)
            await session.commit()
        total_deleted += deleted
        if deleted < batch_size:
            break
        await asyncio.sleep(0)
    return total_deleted

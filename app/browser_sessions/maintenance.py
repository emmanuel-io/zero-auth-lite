"""Periodic cleanup for terminal browser-session persistence."""

import asyncio
from datetime import datetime, UTC
from logging import getLogger
from typing import TYPE_CHECKING

from app.browser_sessions.revocation import BrowserSessionRevocationService


if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

    from app.browser_sessions.settings import BrowserSessionSettings


logger = getLogger(__name__)


async def run_browser_session_cleanup(
    *,
    db_session: "AsyncSession",
    settings: "BrowserSessionSettings",
    now: datetime | None = None,
) -> int:
    """Delete one bounded batch of expired or revoked browser sessions."""
    deleted = await BrowserSessionRevocationService(
        db_session=db_session,
        settings=settings,
    ).cleanup_terminal_sessions(now=now)
    await db_session.commit()
    logger.info("Browser-session cleanup removed sessions=%s", deleted)
    return deleted


async def drain_browser_session_cleanup(
    session_factory: "async_sessionmaker[AsyncSession]",
    *,
    settings: "BrowserSessionSettings",
    stop_event: asyncio.Event | None = None,
) -> int:
    """Drain one finite snapshot through bounded cleanup transactions."""
    cutoff = datetime.now(UTC)
    total_deleted = 0
    while stop_event is None or not stop_event.is_set():
        async with session_factory() as db_session:
            deleted = await run_browser_session_cleanup(
                db_session=db_session,
                settings=settings,
                now=cutoff,
            )
        total_deleted += deleted
        if deleted < settings.cleanup_batch_size:
            break
        await asyncio.sleep(0)
    return total_deleted


async def run_browser_session_cleanup_worker(
    session_factory: "async_sessionmaker[AsyncSession]",
    *,
    settings: "BrowserSessionSettings",
    stop_event: asyncio.Event,
) -> None:
    """Run browser-session cleanup immediately and at a fixed interval."""
    while not stop_event.is_set():
        try:
            await drain_browser_session_cleanup(
                session_factory,
                settings=settings,
                stop_event=stop_event,
            )
        except Exception:
            logger.exception("Browser-session maintenance run failed")
        try:
            await asyncio.wait_for(
                stop_event.wait(), timeout=settings.cleanup_interval_seconds
            )
        except TimeoutError:
            continue

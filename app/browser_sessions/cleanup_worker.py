"""Dedicated process entry point for browser-session cleanup."""

from __future__ import annotations

import argparse
import asyncio
from typing import TYPE_CHECKING

from app.browser_sessions.maintenance import (
    drain_browser_session_cleanup,
    run_browser_session_cleanup_worker,
)
from app.core.logs.config import configure_logging
from app.core.worker import worker_stop_event
from app.db.worker import open_worker_database
from app.settings.root import load_settings


if TYPE_CHECKING:
    from collections.abc import Sequence

    from app.settings.root import Settings


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse cleanup worker command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Delete expired or revoked browser sessions.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one cleanup for a scheduler instead of staying alive.",
    )
    return parser.parse_args(argv)


async def run_cleanup_process(
    settings: Settings,
    *,
    once: bool,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Run one cleanup or the dedicated periodic cleanup worker."""
    if not settings.browser_session.enabled:
        return
    async with open_worker_database(settings) as session_factory:
        if once:
            await drain_browser_session_cleanup(
                session_factory,
                settings=settings.browser_session,
            )
            return

        with worker_stop_event(stop_event) as worker_stop:
            await run_browser_session_cleanup_worker(
                session_factory,
                settings=settings.browser_session,
                stop_event=worker_stop,
            )


def main(argv: Sequence[str] | None = None) -> None:
    """Load canonical settings and run the selected cleanup mode."""
    args = _parse_args(argv)
    settings = load_settings()
    configure_logging(settings.app.log_level)
    asyncio.run(run_cleanup_process(settings, once=args.once))


if __name__ == "__main__":
    main()

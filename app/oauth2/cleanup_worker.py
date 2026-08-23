"""Dedicated process entry point for OAuth2 persistence cleanup."""

from __future__ import annotations

import argparse
import asyncio
import signal
from contextlib import suppress
from typing import TYPE_CHECKING

from app.core.logs.config import configure_logging
from app.db.engine import create_engine, create_session_factory
from app.db.migrations import ensure_database_is_migrated
from app.oauth2.maintenance import run_oauth2_cleanup, run_oauth2_cleanup_worker
from app.settings.root import load_settings


if TYPE_CHECKING:
    from collections.abc import Sequence

    from app.settings.root import Settings


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse cleanup worker command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Delete expired and terminal OAuth2 persistence records.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one cleanup for a cron job instead of staying alive.",
    )
    return parser.parse_args(argv)


def _install_stop_handlers(stop_event: asyncio.Event) -> tuple[signal.Signals, ...]:
    """Translate supported process signals into cooperative worker shutdown."""
    loop = asyncio.get_running_loop()
    installed: list[signal.Signals] = []
    for process_signal in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(process_signal, stop_event.set)
        except NotImplementedError:
            continue
        installed.append(process_signal)
    return tuple(installed)


async def run_cleanup_process(
    settings: Settings,
    *,
    once: bool,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Run one cleanup or the dedicated periodic cleanup worker."""
    engine = create_engine(settings.db_path, echo=settings.db_echo)
    try:
        await ensure_database_is_migrated(engine)
        session_factory = create_session_factory(engine)
        if once:
            async with session_factory() as db_session:
                await run_oauth2_cleanup(
                    db_session=db_session,
                    batch_size=settings.oauth2.cleanup_batch_size,
                )
            return

        worker_stop = stop_event or asyncio.Event()
        installed_signals = _install_stop_handlers(worker_stop)
        try:
            await run_oauth2_cleanup_worker(
                session_factory,
                interval_seconds=settings.oauth2.cleanup_interval_seconds,
                batch_size=settings.oauth2.cleanup_batch_size,
                stop_event=worker_stop,
            )
        finally:
            loop = asyncio.get_running_loop()
            for process_signal in installed_signals:
                with suppress(NotImplementedError):
                    loop.remove_signal_handler(process_signal)
    finally:
        await engine.dispose()


def main(argv: Sequence[str] | None = None) -> None:
    """Load canonical settings and run the selected cleanup process mode."""
    args = _parse_args(argv)
    settings = load_settings()
    configure_logging(settings.app.log_level)
    asyncio.run(run_cleanup_process(settings, once=args.once))


if __name__ == "__main__":
    main()

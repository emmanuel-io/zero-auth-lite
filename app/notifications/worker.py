"""Dedicated process entry point for durable outbox delivery."""

from __future__ import annotations

import argparse
import asyncio
from contextlib import suppress
from logging import getLogger
from typing import TYPE_CHECKING

from app.core.logs.config import configure_logging
from app.core.worker import worker_stop_event
from app.db.worker import open_worker_database
from app.mail.service import build_mail_service
from app.notifications.dispatcher import run_outbox_dispatcher
from app.settings.root import load_settings


if TYPE_CHECKING:
    from collections.abc import Sequence

    from app.settings.root import Settings

logger = getLogger(__name__)


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the outbox worker command line."""
    parser = argparse.ArgumentParser(
        description="Deliver durable Zero Auth Lite authentication notifications.",
    )
    return parser.parse_args(argv)


async def _stop_dispatcher(task: asyncio.Task[None], *, timeout_seconds: float) -> None:
    """Wait for cooperative shutdown and cancel after the configured deadline."""
    try:
        await asyncio.wait_for(task, timeout=timeout_seconds)
    except TimeoutError:
        logger.warning("Outbox dispatcher did not stop before its deadline.")
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


async def run_outbox_process(
    settings: Settings, *, stop_event: asyncio.Event | None = None
) -> None:
    """Run the dedicated outbox dispatcher until process shutdown."""
    async with open_worker_database(settings) as session_factory:
        mail_service = (
            await asyncio.to_thread(build_mail_service, settings.mail)
            if settings.mail.enabled
            else None
        )
        with worker_stop_event(stop_event) as worker_stop:
            dispatcher_task = asyncio.create_task(
                run_outbox_dispatcher(
                    session_factory,
                    settings,
                    worker_stop,
                    mail_service=mail_service,
                ),
                name="auth-event-outbox-dispatcher",
            )
            stop_wait_task = asyncio.create_task(worker_stop.wait())
            try:
                done, _pending = await asyncio.wait(
                    {dispatcher_task, stop_wait_task},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if dispatcher_task in done:
                    await dispatcher_task
                else:
                    await _stop_dispatcher(
                        dispatcher_task,
                        timeout_seconds=(
                            settings.notification_outbox.shutdown_timeout_seconds
                        ),
                    )
            finally:
                if not stop_wait_task.done():
                    stop_wait_task.cancel()
                    with suppress(asyncio.CancelledError):
                        await stop_wait_task
                if not dispatcher_task.done():
                    dispatcher_task.cancel()
                    with suppress(asyncio.CancelledError):
                        await dispatcher_task


def main(argv: Sequence[str] | None = None) -> None:
    """Load canonical settings and run the outbox process."""
    _parse_args(argv)
    settings = load_settings()
    configure_logging(settings.app.log_level)
    asyncio.run(run_outbox_process(settings))


if __name__ == "__main__":
    main()

"""Dedicated process entry point for durable outbox delivery."""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
from contextlib import suppress
from logging import getLogger
from typing import TYPE_CHECKING

from app.core.logs.config import configure_logging
from app.db.engine import create_engine, create_session_factory
from app.db.migrations import ensure_database_is_migrated
from app.db.snowflake import (
    acquire_snowflake_node_lease,
    configure_snowflake_generator,
    SnowflakeNodeLease,
    unconfigure_snowflake_generator,
)
from app.events.dispatcher import run_outbox_dispatcher
from app.settings.root import load_settings


if TYPE_CHECKING:
    from collections.abc import Sequence

    from app.settings.root import Settings

logger = getLogger(__name__)


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the outbox worker command line."""
    parser = argparse.ArgumentParser(
        description="Deliver durable Zero Auth Lite outbox events.",
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
    engine = create_engine(settings.db_path, echo=settings.db_echo)
    snowflake_lease: SnowflakeNodeLease | None = None
    snowflake_configured = False
    installed_signals: tuple[signal.Signals, ...] = ()
    dispatcher_task: asyncio.Task[None] | None = None
    stop_wait_task: asyncio.Task[bool] | None = None
    try:
        snowflake_lease = acquire_snowflake_node_lease(
            lock_directory=settings.runtime_dir / "snowflake",
            requested_node_id=settings.snowflake_node_id,
        )
        configure_snowflake_generator(snowflake_lease.node_id)
        snowflake_configured = True
        logger.info(
            "Outbox Snowflake node acquired pid=%s node_id=%s",
            os.getpid(),
            snowflake_lease.node_id,
        )
        await ensure_database_is_migrated(engine)
        session_factory = create_session_factory(engine)
        worker_stop = stop_event or asyncio.Event()
        if stop_event is None:
            installed_signals = _install_stop_handlers(worker_stop)
        dispatcher_task = asyncio.create_task(
            run_outbox_dispatcher(
                session_factory,
                settings,
                worker_stop,
            ),
            name="auth-event-outbox-dispatcher",
        )
        stop_wait_task = asyncio.create_task(worker_stop.wait())
        done, _pending = await asyncio.wait(
            {dispatcher_task, stop_wait_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if dispatcher_task in done:
            await dispatcher_task
        else:
            await _stop_dispatcher(
                dispatcher_task,
                timeout_seconds=settings.events.shutdown_timeout_seconds,
            )
    finally:
        if stop_wait_task is not None and not stop_wait_task.done():
            stop_wait_task.cancel()
            with suppress(asyncio.CancelledError):
                await stop_wait_task
        if dispatcher_task is not None and not dispatcher_task.done():
            dispatcher_task.cancel()
            with suppress(asyncio.CancelledError):
                await dispatcher_task
        loop = asyncio.get_running_loop()
        for process_signal in installed_signals:
            with suppress(NotImplementedError):
                loop.remove_signal_handler(process_signal)
        await engine.dispose()
        if snowflake_configured:
            unconfigure_snowflake_generator()
        if snowflake_lease is not None:
            snowflake_lease.release()


def main(argv: Sequence[str] | None = None) -> None:
    """Load canonical settings and run the outbox process."""
    _parse_args(argv)
    settings = load_settings()
    configure_logging(settings.app.log_level)
    asyncio.run(run_outbox_process(settings))


if __name__ == "__main__":
    main()

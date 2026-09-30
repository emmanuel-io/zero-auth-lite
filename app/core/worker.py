"""Shared process-control helpers for dedicated workers."""

import asyncio
import signal
from collections.abc import Iterator
from contextlib import contextmanager, suppress


def install_stop_signal_handlers(
    stop_event: asyncio.Event,
) -> tuple[signal.Signals, ...]:
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


@contextmanager
def worker_stop_event(
    external_stop_event: asyncio.Event | None = None,
) -> Iterator[asyncio.Event]:
    """Provide cooperative shutdown and own signals only for process execution."""
    stop_event = external_stop_event or asyncio.Event()
    installed_signals = (
        ()
        if external_stop_event is not None
        else install_stop_signal_handlers(stop_event)
    )
    try:
        yield stop_event
    finally:
        if installed_signals:
            loop = asyncio.get_running_loop()
            for process_signal in installed_signals:
                with suppress(NotImplementedError):
                    loop.remove_signal_handler(process_signal)

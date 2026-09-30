"""Tests for shared dedicated-worker lifecycle helpers."""

import asyncio
import signal
from collections.abc import Callable
from typing import Never

import pytest

from app.core import worker


pytestmark = pytest.mark.unit


class FakeSignalLoop:
    """Record signal registrations and optionally reject one signal."""

    def __init__(self, *, unsupported: signal.Signals | None = None) -> None:
        """Initialize the fake loop and its registration record."""
        self.unsupported = unsupported
        self.registered: list[tuple[signal.Signals, Callable[[], None]]] = []

    def add_signal_handler(
        self, process_signal: signal.Signals, callback: Callable[[], None]
    ) -> None:
        """Record a supported handler or emulate an unsupported platform."""
        if process_signal == self.unsupported:
            raise NotImplementedError
        self.registered.append((process_signal, callback))


def test_install_stop_signal_handlers_registers_supported_signals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Register cooperative shutdown for both standard process signals."""
    loop = FakeSignalLoop()
    stop_event = asyncio.Event()
    monkeypatch.setattr(asyncio, "get_running_loop", lambda: loop)

    installed = worker.install_stop_signal_handlers(stop_event)

    assert installed == (signal.SIGINT, signal.SIGTERM)
    assert [item[0] for item in loop.registered] == list(installed)
    loop.registered[0][1]()
    assert stop_event.is_set()


def test_install_stop_signal_handlers_skips_unsupported_signals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep workers usable where event-loop signal handlers are unavailable."""
    loop = FakeSignalLoop(unsupported=signal.SIGTERM)
    monkeypatch.setattr(asyncio, "get_running_loop", lambda: loop)

    installed = worker.install_stop_signal_handlers(asyncio.Event())

    assert installed == (signal.SIGINT,)


def test_external_stop_event_does_not_install_process_signals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Leave signal ownership to tests or embedding process callers."""
    external_stop_event = asyncio.Event()

    def unexpected_install(_stop_event: asyncio.Event) -> Never:
        pytest.fail("external stop events must not install process signals")

    monkeypatch.setattr(worker, "install_stop_signal_handlers", unexpected_install)

    with worker.worker_stop_event(external_stop_event) as stop_event:
        assert stop_event is external_stop_event

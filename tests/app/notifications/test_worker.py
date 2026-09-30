"""Unit tests for the dedicated outbox worker process."""

import asyncio
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager

import pytest
from app.settings.root import Settings

from app.notifications import worker


pytestmark = pytest.mark.unit


class DispatcherError(RuntimeError):
    """Represent a synthetic dispatcher failure."""


@pytest.mark.asyncio
async def test_outbox_process_bounds_shutdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cancel a dispatcher that ignores cooperative worker shutdown."""
    lifecycle: list[str] = []
    session_factory = object()
    cancelled = asyncio.Event()

    @asynccontextmanager
    async def fake_worker_database(_settings: object) -> AsyncIterator[object]:
        lifecycle.append("database entered")
        try:
            yield session_factory
        finally:
            lifecycle.append("database exited")

    @contextmanager
    def fake_worker_stop_event(
        external_stop_event: asyncio.Event | None,
    ) -> Iterator[asyncio.Event]:
        lifecycle.append("stop event entered")
        assert external_stop_event is not None
        try:
            yield external_stop_event
        finally:
            lifecycle.append("stop event exited")

    monkeypatch.setattr(worker, "open_worker_database", fake_worker_database)
    monkeypatch.setattr(worker, "worker_stop_event", fake_worker_stop_event)
    mail_service = object()
    mail_service_builds: list[object] = []

    def fake_build_mail_service(settings: object) -> object:
        mail_service_builds.append(settings)
        return mail_service

    monkeypatch.setattr(worker, "build_mail_service", fake_build_mail_service)

    async def stuck_dispatcher(
        received_session_factory: object,
        _settings: object,
        received_stop_event: asyncio.Event,
        **kwargs: object,
    ) -> None:
        assert received_session_factory is session_factory
        assert received_stop_event.is_set()
        assert kwargs["mail_service"] is mail_service
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    monkeypatch.setattr(worker, "run_outbox_dispatcher", stuck_dispatcher)

    stop_event = asyncio.Event()
    stop_event.set()
    await worker.run_outbox_process(
        Settings(notification_outbox={"shutdown_timeout_seconds": 0.01}),
        stop_event=stop_event,
    )

    assert cancelled.is_set()
    assert len(mail_service_builds) == 1
    assert lifecycle == [
        "database entered",
        "stop event entered",
        "stop event exited",
        "database exited",
    ]


@pytest.mark.asyncio
async def test_outbox_process_releases_resources_after_dispatcher_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Release worker resources when the dispatcher fails unexpectedly."""
    lifecycle: list[str] = []

    @asynccontextmanager
    async def fake_worker_database(_settings: object) -> AsyncIterator[object]:
        lifecycle.append("database entered")
        try:
            yield object()
        finally:
            lifecycle.append("database exited")

    @contextmanager
    def fake_worker_stop_event(
        external_stop_event: asyncio.Event | None,
    ) -> Iterator[asyncio.Event]:
        lifecycle.append("stop event entered")
        assert external_stop_event is not None
        try:
            yield external_stop_event
        finally:
            lifecycle.append("stop event exited")

    async def failing_dispatcher(*_args: object, **_kwargs: object) -> None:
        raise DispatcherError

    monkeypatch.setattr(worker, "open_worker_database", fake_worker_database)
    monkeypatch.setattr(worker, "worker_stop_event", fake_worker_stop_event)
    monkeypatch.setattr(worker, "run_outbox_dispatcher", failing_dispatcher)

    with pytest.raises(DispatcherError):
        await worker.run_outbox_process(Settings(), stop_event=asyncio.Event())

    assert lifecycle == [
        "database entered",
        "stop event entered",
        "stop event exited",
        "database exited",
    ]

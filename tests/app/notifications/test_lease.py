"""Integration tests for durable notification outbox leases."""

from datetime import datetime, timedelta, UTC
from uuid import uuid4

import pytest
from app.db.models.notification_outbox import NotificationOutboxDB
from app.notifications.lease import _claim_pending, _retry_delay_seconds
from fastapi import FastAPI
from sqlalchemy import update


pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    ("attempt_count", "expected"),
    [(1, 2), (8, 256), (9, 300), (1_000_000, 300)],
)
def test_retry_delay_reaches_configured_ceiling(
    attempt_count: int, expected: int
) -> None:
    """Cap exponential retry at the configured value for every attempt count."""
    assert _retry_delay_seconds(attempt_count=attempt_count, maximum=300) == expected


@pytest.mark.asyncio
async def test_claim_is_exclusive_and_expired_lease_is_recoverable(
    app: FastAPI,
) -> None:
    """Only one worker owns a live lease, while a crashed lease is reclaimed."""
    now = datetime.now(UTC)
    event_id = uuid4().hex
    async with app.state.core_session_factory() as seed_session:
        seed_session.add(
            NotificationOutboxDB(
                event_id=event_id,
                event_type="auth.account_verification_requested",
                payload={},
                occurred_at=now,
                available_at=now,
            )
        )
        await seed_session.commit()

    async with app.state.core_session_factory() as first_session:
        first = await _claim_pending(
            first_session,
            worker_id="worker-one",
            now=now,
            settings=app.state.settings.notification_outbox,
        )
    async with app.state.core_session_factory() as second_session:
        second = await _claim_pending(
            second_session,
            worker_id="worker-two",
            now=now,
            settings=app.state.settings.notification_outbox,
        )
        await second_session.execute(
            update(NotificationOutboxDB)
            .where(NotificationOutboxDB.event_id == event_id)
            .values(
                claimed_at=now
                - timedelta(
                    seconds=app.state.settings.notification_outbox.lease_seconds + 1
                )
            )
        )
        await second_session.commit()
    async with app.state.core_session_factory() as recovered_session:
        recovered = await _claim_pending(
            recovered_session,
            worker_id="worker-two",
            now=now,
            settings=app.state.settings.notification_outbox,
        )

    assert len(first) == 1
    assert second == []
    assert recovered == first

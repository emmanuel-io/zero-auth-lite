"""Integration tests for persisted user email lifecycle invariants."""

from datetime import datetime, UTC

import pytest
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.emails import create_user_email, retire_email
from app.identity.users.enums import UserEmailStatus
from fastapi import FastAPI
from sqlalchemy import insert, select
from sqlalchemy.exc import IntegrityError


pytestmark = pytest.mark.integration


async def _create_user(app: FastAPI) -> int:
    """Persist a minimal account and return its internal identifier."""
    async with app.state.core_session_factory() as session:
        user_id = await session.scalar(
            insert(UserDB)
            .values(hashed_password="unused")  # noqa: S106
            .returning(UserDB.id)
        )
        assert user_id is not None
        await session.commit()
        return user_id


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("first_status", "second_status"),
    [
        (UserEmailStatus.CURRENT, UserEmailStatus.CURRENT),
        (UserEmailStatus.PENDING, UserEmailStatus.PENDING),
    ],
)
async def test_user_has_at_most_one_email_in_each_active_state(
    app: FastAPI,
    first_status: UserEmailStatus,
    second_status: UserEmailStatus,
) -> None:
    """Enforce one current and one pending address per user in SQLite."""
    user_id = await _create_user(app)
    async with app.state.core_session_factory() as session:
        session.add(
            UserEmailDB(
                user_id=user_id,
                email=f"first-{first_status}@example.com",
                normalized_email=f"first-{first_status}@example.com",
                status=first_status,
            )
        )
        await session.commit()
        session.add(
            UserEmailDB(
                user_id=user_id,
                email=f"second-{second_status}@example.com",
                normalized_email=f"second-{second_status}@example.com",
                status=second_status,
            )
        )
        with pytest.raises(IntegrityError):
            await session.flush()


@pytest.mark.asyncio
async def test_active_normalized_email_is_unique_across_users(app: FastAPI) -> None:
    """Prevent current and pending addresses from claiming the same identity."""
    current_user_id = await _create_user(app)
    pending_user_id = await _create_user(app)
    async with app.state.core_session_factory() as session:
        session.add(
            UserEmailDB(
                user_id=current_user_id,
                email="Unique@Example.com",
                normalized_email="unique@example.com",
                status=UserEmailStatus.CURRENT,
            )
        )
        await session.commit()
        session.add(
            UserEmailDB(
                user_id=pending_user_id,
                email="unique@example.com",
                normalized_email="unique@example.com",
                status=UserEmailStatus.PENDING,
            )
        )
        with pytest.raises(IntegrityError):
            await session.flush()


@pytest.mark.asyncio
async def test_retired_email_can_be_reused_and_preserves_history(app: FastAPI) -> None:
    """Release normalized ownership while retaining the retired address row."""
    first_user_id = await _create_user(app)
    second_user_id = await _create_user(app)
    async with app.state.core_session_factory() as session:
        original = await create_user_email(
            session,
            user_id=first_user_id,
            email="Reusable@Example.com",
            status=UserEmailStatus.CURRENT,
            verified_at=datetime.now(UTC),
        )
        await retire_email(session, email=original)
        replacement = await create_user_email(
            session,
            user_id=second_user_id,
            email="reusable@example.com",
            status=UserEmailStatus.CURRENT,
        )
        await session.commit()

        history = list(
            await session.scalars(select(UserEmailDB).order_by(UserEmailDB.id))
        )

    assert original.status == UserEmailStatus.RETIRED
    assert original.retired_at is not None
    assert replacement.status == UserEmailStatus.CURRENT
    assert [row.email for row in history] == [
        "Reusable@example.com",
        "reusable@example.com",
    ]
    assert {row.normalized_email for row in history} == {"reusable@example.com"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "verified_at", "retired_at"),
    [
        (UserEmailStatus.PENDING, datetime.now(UTC), None),
        (UserEmailStatus.PENDING, None, datetime.now(UTC)),
        (UserEmailStatus.CURRENT, None, datetime.now(UTC)),
        (UserEmailStatus.RETIRED, None, None),
    ],
)
async def test_email_state_timestamps_are_constrained(
    app: FastAPI,
    status: UserEmailStatus,
    verified_at: datetime | None,
    retired_at: datetime | None,
) -> None:
    """Reject timestamp combinations that contradict an address state."""
    user_id = await _create_user(app)
    async with app.state.core_session_factory() as session:
        session.add(
            UserEmailDB(
                user_id=user_id,
                email=f"invalid-{status}@example.com",
                normalized_email=f"invalid-{status}@example.com",
                status=status,
                verified_at=verified_at,
                retired_at=retired_at,
            )
        )
        with pytest.raises(IntegrityError):
            await session.flush()

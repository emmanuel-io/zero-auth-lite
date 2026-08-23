"""Persistence helpers for current, pending, and retired user emails."""

from datetime import datetime, UTC
from typing import cast

from pydantic import TypeAdapter
from sqlalchemy import insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Load, selectinload

from app.db.models.auth_token import UserAuthTokenDB
from app.db.models.user import UserDB, UserEmailDB
from app.errors import ObjectAlreadyExistsError
from app.identity.users.enums import UserEmailStatus
from app.identity.users.types import UserEmail


_USER_EMAIL_ADAPTER = TypeAdapter(UserEmail)
_ACTIVE_EMAIL_STATUSES = (UserEmailStatus.CURRENT, UserEmailStatus.PENDING)


def validate_user_email(email: str) -> UserEmail:
    """Validate an email with the canonical identity-domain constraints."""
    return _USER_EMAIL_ADAPTER.validate_python(email)


def normalize_email(email: str) -> str:
    """Return the canonical representation used for matching and uniqueness."""
    return email.strip().lower()


def active_email_loader() -> Load:
    """Load only the bounded current and pending collection for a user."""
    return cast(
        "Load",
        selectinload(
            UserDB.emails.and_(UserEmailDB.status.in_(_ACTIVE_EMAIL_STATUSES))
        ),
    )


async def email_is_available(
    db_session: AsyncSession,
    *,
    email: str,
    excluding_user_id: int | None,
) -> bool:
    """Return whether no current or pending row claims the normalized address."""
    statement = (
        select(UserEmailDB.id)
        .where(UserEmailDB.normalized_email == normalize_email(email))
        .where(UserEmailDB.status.in_(_ACTIVE_EMAIL_STATUSES))
    )
    if excluding_user_id is not None:
        statement = statement.where(UserEmailDB.user_id != excluding_user_id)
    return await db_session.scalar(statement.limit(1)) is None


async def create_user_email(
    db_session: AsyncSession,
    *,
    user_id: int,
    email: str,
    status: UserEmailStatus,
    verified_at: datetime | None = None,
) -> UserEmailDB:
    """Create one address and translate an active-address uniqueness race."""
    display_email = str(validate_user_email(email)).strip()
    try:
        async with db_session.begin_nested():
            row = (
                await db_session.execute(
                    insert(UserEmailDB)
                    .values(
                        user_id=user_id,
                        email=display_email,
                        normalized_email=normalize_email(display_email),
                        status=status,
                        verified_at=verified_at,
                    )
                    .returning(UserEmailDB)
                )
            ).scalar_one()
    except IntegrityError as exc:
        raise ObjectAlreadyExistsError from exc
    await db_session.flush()
    return row


async def email_for_user(
    db_session: AsyncSession, *, user_id: int, status: UserEmailStatus
) -> UserEmailDB | None:
    """Load one explicitly selected email state for a user."""
    email: UserEmailDB | None = await db_session.scalar(
        select(UserEmailDB).where(
            UserEmailDB.user_id == user_id,
            UserEmailDB.status == status,
        )
    )
    return email


async def retire_email(db_session: AsyncSession, *, email: UserEmailDB) -> None:
    """Retire an address and invalidate every unused token bound to it."""
    if email.status == UserEmailStatus.RETIRED:
        return
    now = datetime.now(UTC)
    await db_session.execute(
        update(UserAuthTokenDB)
        .where(UserAuthTokenDB.user_email_id == email.id)
        .where(UserAuthTokenDB.used_at.is_(None))
        .values(used_at=now)
    )
    email.status = UserEmailStatus.RETIRED
    email.retired_at = now
    await db_session.flush()

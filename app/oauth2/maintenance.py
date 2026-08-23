"""OAuth2 persistence maintenance helpers."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, UTC
from logging import getLogger
from typing import Any, cast, TYPE_CHECKING

from sqlalchemy import delete, exists, or_, select

from app.db.models.oauth2_authorization_code import (
    OAuth2AuthorizationCodeDB,
)
from app.db.models.oauth2_authorization_transaction import (
    OAuth2AuthorizationTransactionDB,
)
from app.db.models.oauth2_device_authorization import (
    OAuth2DeviceAuthorizationDB,
)
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_pair import OAuth2TokenPairDB


if TYPE_CHECKING:
    from sqlalchemy.engine import CursorResult, Result
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
    from sqlalchemy.sql.elements import ColumnElement


logger = getLogger(__name__)


@dataclass(frozen=True, slots=True)
class OAuth2CleanupResult:
    """Counts of rows deleted by one OAuth2 cleanup run."""

    authorization_codes: int
    authorization_transactions: int
    device_authorizations: int
    token_pairs: int
    sessions: int


def _rowcount(result: Result[Any]) -> int:
    """Return a normalized affected-row count from a SQLAlchemy result."""
    return int(cast("CursorResult[Any]", result).rowcount or 0)


async def run_oauth2_cleanup(
    *,
    db_session: AsyncSession,
    now: datetime | None = None,
    batch_size: int = 100,
) -> OAuth2CleanupResult:
    """Delete bounded batches of expired or terminal OAuth2 rows."""
    cutoff = now or datetime.now(UTC)
    authorization_code_ids = (
        select(OAuth2AuthorizationCodeDB.id)
        .where(
            or_(
                OAuth2AuthorizationCodeDB.expires_at <= cutoff,
                OAuth2AuthorizationCodeDB.used_at.is_not(None),
            )
        )
        .order_by(OAuth2AuthorizationCodeDB.id)
        .limit(batch_size)
    )
    authorization_codes = _rowcount(
        await db_session.execute(
            delete(OAuth2AuthorizationCodeDB).where(
                OAuth2AuthorizationCodeDB.id.in_(authorization_code_ids)
            )
        )
    )
    authorization_transaction_ids = (
        select(OAuth2AuthorizationTransactionDB.id)
        .where(
            or_(
                OAuth2AuthorizationTransactionDB.expires_at <= cutoff,
                OAuth2AuthorizationTransactionDB.used_at.is_not(None),
            )
        )
        .order_by(OAuth2AuthorizationTransactionDB.id)
        .limit(batch_size)
    )
    authorization_transactions = _rowcount(
        await db_session.execute(
            delete(OAuth2AuthorizationTransactionDB).where(
                OAuth2AuthorizationTransactionDB.id.in_(authorization_transaction_ids)
            )
        )
    )
    device_authorization_ids = (
        select(OAuth2DeviceAuthorizationDB.id)
        .where(
            or_(
                OAuth2DeviceAuthorizationDB.expires_at <= cutoff,
                OAuth2DeviceAuthorizationDB.used_at.is_not(None),
                OAuth2DeviceAuthorizationDB.denied_at.is_not(None),
            )
        )
        .order_by(OAuth2DeviceAuthorizationDB.id)
        .limit(batch_size)
    )
    device_authorizations = _rowcount(
        await db_session.execute(
            delete(OAuth2DeviceAuthorizationDB).where(
                OAuth2DeviceAuthorizationDB.id.in_(device_authorization_ids)
            )
        )
    )
    token_pair_session_ids = (
        select(OAuth2TokenPairDB.session_id)
        .where(
            or_(
                OAuth2TokenPairDB.refresh_expires_at <= cutoff,
                (
                    OAuth2TokenPairDB.refresh_expires_at.is_(None)
                    & (OAuth2TokenPairDB.access_expires_at <= cutoff)
                ),
            )
        )
        .order_by(OAuth2TokenPairDB.session_id)
        .limit(batch_size)
    )
    token_pairs = _rowcount(
        await db_session.execute(
            delete(OAuth2TokenPairDB).where(
                OAuth2TokenPairDB.session_id.in_(token_pair_session_ids)
            )
        )
    )
    session_terminal: ColumnElement[bool] = or_(
        OAuth2SessionDB.ended_at.is_not(None),
        ~exists(
            select(OAuth2TokenPairDB.session_id).where(
                OAuth2TokenPairDB.session_id == OAuth2SessionDB.id
            )
        ),
    )
    terminal_session_ids = (
        select(OAuth2SessionDB.id)
        .where(session_terminal)
        .order_by(OAuth2SessionDB.id)
        .limit(batch_size)
    )
    sessions = _rowcount(
        await db_session.execute(
            delete(OAuth2SessionDB).where(OAuth2SessionDB.id.in_(terminal_session_ids))
        )
    )
    await db_session.commit()
    result = OAuth2CleanupResult(
        authorization_codes=authorization_codes,
        authorization_transactions=authorization_transactions,
        device_authorizations=device_authorizations,
        token_pairs=token_pairs,
        sessions=sessions,
    )
    logger.info(
        "OAuth2 cleanup removed authorization_codes=%s "
        "authorization_transactions=%s device_authorizations=%s "
        "token_pairs=%s sessions=%s",
        result.authorization_codes,
        result.authorization_transactions,
        result.device_authorizations,
        result.token_pairs,
        result.sessions,
    )
    return result


async def run_oauth2_cleanup_worker(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    interval_seconds: int,
    batch_size: int,
    stop_event: asyncio.Event,
) -> None:
    """Run OAuth2 cleanup immediately and then at a fixed interval."""
    while not stop_event.is_set():
        try:
            async with session_factory() as db_session:
                await run_oauth2_cleanup(
                    db_session=db_session,
                    batch_size=batch_size,
                )
        except Exception:
            logger.exception("OAuth2 maintenance run failed")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
        except TimeoutError:
            continue

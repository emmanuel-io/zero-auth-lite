"""OAuth2 persistence maintenance helpers."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, UTC
from logging import getLogger
from typing import Any, cast, TYPE_CHECKING

from sqlalchemy import delete, exists, or_, select, union

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
from app.db.models.oauth2_token_state import OAuth2TokenStateDB


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
    token_states: int
    sessions: int


def _combine_cleanup_results(
    left: OAuth2CleanupResult, right: OAuth2CleanupResult
) -> OAuth2CleanupResult:
    """Add per-table cleanup counts without hiding their meaning."""
    return OAuth2CleanupResult(
        authorization_codes=left.authorization_codes + right.authorization_codes,
        authorization_transactions=(
            left.authorization_transactions + right.authorization_transactions
        ),
        device_authorizations=(
            left.device_authorizations + right.device_authorizations
        ),
        token_states=left.token_states + right.token_states,
        sessions=left.sessions + right.sessions,
    )


def _cleanup_may_have_more(result: OAuth2CleanupResult, *, batch_size: int) -> bool:
    """Return whether any table filled its bounded batch."""
    return any(
        count == batch_size
        for count in (
            result.authorization_codes,
            result.authorization_transactions,
            result.device_authorizations,
            result.token_states,
            result.sessions,
        )
    )


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
    authorization_code_candidates = union(
        select(OAuth2AuthorizationCodeDB.id).where(
            OAuth2AuthorizationCodeDB.expires_at <= cutoff
        ),
        select(OAuth2AuthorizationCodeDB.id).where(
            OAuth2AuthorizationCodeDB.used_at.is_not(None)
        ),
    ).subquery()
    authorization_code_ids = (
        select(authorization_code_candidates.c.id)
        .order_by(authorization_code_candidates.c.id)
        .limit(batch_size)
    )
    authorization_codes = _rowcount(
        await db_session.execute(
            delete(OAuth2AuthorizationCodeDB).where(
                OAuth2AuthorizationCodeDB.id.in_(authorization_code_ids)
            )
        )
    )
    authorization_transaction_candidates = union(
        select(OAuth2AuthorizationTransactionDB.id).where(
            OAuth2AuthorizationTransactionDB.expires_at <= cutoff
        ),
        select(OAuth2AuthorizationTransactionDB.id).where(
            OAuth2AuthorizationTransactionDB.used_at.is_not(None)
        ),
    ).subquery()
    authorization_transaction_ids = (
        select(authorization_transaction_candidates.c.id)
        .order_by(authorization_transaction_candidates.c.id)
        .limit(batch_size)
    )
    authorization_transactions = _rowcount(
        await db_session.execute(
            delete(OAuth2AuthorizationTransactionDB).where(
                OAuth2AuthorizationTransactionDB.id.in_(authorization_transaction_ids)
            )
        )
    )
    device_authorization_candidates = union(
        select(OAuth2DeviceAuthorizationDB.id).where(
            OAuth2DeviceAuthorizationDB.expires_at <= cutoff
        ),
        select(OAuth2DeviceAuthorizationDB.id).where(
            OAuth2DeviceAuthorizationDB.used_at.is_not(None)
        ),
        select(OAuth2DeviceAuthorizationDB.id).where(
            OAuth2DeviceAuthorizationDB.denied_at.is_not(None)
        ),
    ).subquery()
    device_authorization_ids = (
        select(device_authorization_candidates.c.id)
        .order_by(device_authorization_candidates.c.id)
        .limit(batch_size)
    )
    device_authorizations = _rowcount(
        await db_session.execute(
            delete(OAuth2DeviceAuthorizationDB).where(
                OAuth2DeviceAuthorizationDB.id.in_(device_authorization_ids)
            )
        )
    )
    token_state_session_ids = (
        select(OAuth2TokenStateDB.session_id)
        .where(
            or_(
                OAuth2TokenStateDB.refresh_expires_at <= cutoff,
                (
                    OAuth2TokenStateDB.refresh_expires_at.is_(None)
                    & (OAuth2TokenStateDB.access_expires_at <= cutoff)
                ),
            )
        )
        .order_by(OAuth2TokenStateDB.session_id)
        .limit(batch_size)
    )
    token_states = _rowcount(
        await db_session.execute(
            delete(OAuth2TokenStateDB).where(
                OAuth2TokenStateDB.session_id.in_(token_state_session_ids)
            )
        )
    )
    session_terminal: ColumnElement[bool] = or_(
        OAuth2SessionDB.ended_at.is_not(None),
        ~exists(
            select(OAuth2TokenStateDB.session_id).where(
                OAuth2TokenStateDB.session_id == OAuth2SessionDB.id
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
        token_states=token_states,
        sessions=sessions,
    )
    logger.info(
        "OAuth2 cleanup removed authorization_codes=%s "
        "authorization_transactions=%s device_authorizations=%s "
        "token_states=%s sessions=%s",
        result.authorization_codes,
        result.authorization_transactions,
        result.device_authorizations,
        result.token_states,
        result.sessions,
    )
    return result


async def drain_oauth2_cleanup(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    batch_size: int,
    stop_event: asyncio.Event | None = None,
) -> OAuth2CleanupResult:
    """Drain one finite snapshot through bounded cleanup transactions."""
    cutoff = datetime.now(UTC)
    total = OAuth2CleanupResult(0, 0, 0, 0, 0)
    while stop_event is None or not stop_event.is_set():
        async with session_factory() as db_session:
            result = await run_oauth2_cleanup(
                db_session=db_session,
                now=cutoff,
                batch_size=batch_size,
            )
        total = _combine_cleanup_results(total, result)
        if not _cleanup_may_have_more(result, batch_size=batch_size):
            break
        await asyncio.sleep(0)
    return total


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
            await drain_oauth2_cleanup(
                session_factory,
                batch_size=batch_size,
                stop_event=stop_event,
            )
        except Exception:
            logger.exception("OAuth2 maintenance run failed")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
        except TimeoutError:
            continue

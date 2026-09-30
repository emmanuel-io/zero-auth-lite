"""OAuth2 session and token-family status calculations."""

from datetime import datetime, UTC

from sqlalchemy import and_, or_
from sqlalchemy.sql.elements import ColumnElement

from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_state import OAuth2TokenStateDB
from app.oauth2.sessions.dtos import OAuth2SessionReadDTO
from app.oauth2.tokens.dtos import OAuth2TokenStateReadDTO


def token_family_is_current(
    token_state: OAuth2TokenStateReadDTO,
    oauth2_session: OAuth2SessionReadDTO,
    *,
    now: datetime | None = None,
) -> bool:
    """Return whether persisted session state and expiry remain current."""
    if not oauth2_session.is_active():
        return False
    effective_expiry = token_state.refresh_expires_at or token_state.access_expires_at
    if effective_expiry.tzinfo is None or effective_expiry.utcoffset() is None:
        effective_expiry = effective_expiry.replace(tzinfo=UTC)
    else:
        effective_expiry = effective_expiry.astimezone(UTC)
    return effective_expiry > (now or datetime.now(UTC))


def token_family_is_current_predicate(*, now: datetime) -> ColumnElement[bool]:
    """Build the SQL predicate matching :func:`token_family_is_current`."""
    return and_(
        OAuth2SessionDB.ended_at.is_(None),
        or_(
            OAuth2TokenStateDB.refresh_expires_at > now,
            and_(
                OAuth2TokenStateDB.refresh_expires_at.is_(None),
                OAuth2TokenStateDB.access_expires_at > now,
            ),
        ),
    )

"""ORM-to-DTO mapping for browser sessions."""

from app.browser_sessions.dtos import SessionReadDTO
from app.core.time import as_utc_aware
from app.db.models.browser_session import BrowserSessionDB
from app.public_ids import PublicId


def to_session_dto(session: BrowserSessionDB) -> SessionReadDTO:
    """Convert a browser-session row to its stable DTO."""
    return SessionReadDTO(
        stored_session_id=session.id,
        public_id=PublicId(session.public_id),
        user_id=session.user_id,
        csrf=session.csrf,
        absolute_expires_at=as_utc_aware(session.absolute_expires_at),
        created_at=as_utc_aware(session.created_at),
        expires_at=as_utc_aware(session.expires_at),
        ip_hash=session.ip_hash,
        last_seen_at=as_utc_aware(session.last_seen_at),
        revoked_at=(
            as_utc_aware(session.revoked_at) if session.revoked_at is not None else None
        ),
        revoked_reason=session.revoked_reason,
        updated_at=as_utc_aware(session.updated_at),
        user_agent_hash=session.user_agent_hash,
    )

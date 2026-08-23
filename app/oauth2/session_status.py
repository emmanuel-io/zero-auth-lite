"""OAuth2 session and token-family status calculations."""

from datetime import datetime, UTC

from app.oauth2.session_dtos import OAuth2SessionReadDTO
from app.oauth2.tokens.dtos import TokenPairReadDTO


def token_family_is_active(
    token_pair: TokenPairReadDTO,
    oauth2_session: OAuth2SessionReadDTO,
    *,
    now: datetime | None = None,
) -> bool:
    """Return whether a token family still has usable session authority."""
    if not oauth2_session.is_active():
        return False
    effective_expiry = token_pair.refresh_expires_at or token_pair.access_expires_at
    if effective_expiry.tzinfo is None or effective_expiry.utcoffset() is None:
        effective_expiry = effective_expiry.replace(tzinfo=UTC)
    else:
        effective_expiry = effective_expiry.astimezone(UTC)
    return effective_expiry > (now or datetime.now(UTC))

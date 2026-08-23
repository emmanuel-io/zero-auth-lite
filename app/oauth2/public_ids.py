"""Public identifier formatting for OAuth2 administration resources."""

from app.public_ids import (
    format_prefixed_public_id,
    parse_prefixed_public_id,
    public_id_pattern,
    PublicId,
)


OAUTH2_SESSION_ID_PREFIX = "oas"
OAUTH2_SESSION_ID_PATTERN = public_id_pattern(OAUTH2_SESSION_ID_PREFIX)


def format_oauth2_session_id(public_id: PublicId | int) -> str:
    """Format an OAuth2 session's public identifier."""
    return format_prefixed_public_id(public_id, prefix=OAUTH2_SESSION_ID_PREFIX)


def parse_oauth2_session_id(value: str) -> PublicId:
    """Parse a formatted OAuth2 session identifier."""
    try:
        return parse_prefixed_public_id(value, prefix=OAUTH2_SESSION_ID_PREFIX)
    except ValueError as exc:
        msg = f"Invalid OAuth2 session identifier: {value}"
        raise ValueError(msg) from exc

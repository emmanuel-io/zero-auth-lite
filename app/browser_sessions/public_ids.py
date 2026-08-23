"""Public identifier formatting for browser sessions."""

from app.public_ids import (
    format_prefixed_public_id,
    parse_prefixed_public_id,
    public_id_pattern,
    PublicId,
)


BROWSER_SESSION_ID_PREFIX = "ses"
BROWSER_SESSION_ID_PATTERN = public_id_pattern(BROWSER_SESSION_ID_PREFIX)


def format_browser_session_id(public_id: PublicId | int) -> str:
    """Format a browser session's public identifier."""
    return format_prefixed_public_id(public_id, prefix=BROWSER_SESSION_ID_PREFIX)


def parse_browser_session_id(value: str) -> PublicId:
    """Parse a formatted browser-session identifier."""
    try:
        return parse_prefixed_public_id(value, prefix=BROWSER_SESSION_ID_PREFIX)
    except ValueError as exc:
        msg = f"Invalid browser session identifier: {value}"
        raise ValueError(msg) from exc

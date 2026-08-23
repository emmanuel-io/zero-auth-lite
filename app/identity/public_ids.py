"""Formatting helpers for public user and organization identifiers."""

from app.public_ids import (
    format_prefixed_public_id,
    parse_prefixed_public_id,
    public_id_pattern,
    PublicId,
)


USER_ID_PREFIX = "usr"
ORGANIZATION_ID_PREFIX = "org"
USER_ID_PATTERN = public_id_pattern(USER_ID_PREFIX)
ORGANIZATION_ID_PATTERN = public_id_pattern(ORGANIZATION_ID_PREFIX)


def format_user_id(public_id: PublicId | int) -> str:
    """Format a public user identifier as a stable JWT subject."""
    return format_prefixed_public_id(public_id, prefix=USER_ID_PREFIX)


def format_organization_id(public_id: PublicId | int) -> str:
    """Format a public organization identifier as a stable JWT organization claim."""
    return format_prefixed_public_id(public_id, prefix=ORGANIZATION_ID_PREFIX)


def parse_user_id(value: str) -> PublicId:
    """Parse a formatted public user identifier."""
    return _parse_public_id(value, prefix=USER_ID_PREFIX)


def parse_organization_id(value: str) -> PublicId:
    """Parse a formatted public organization identifier."""
    return _parse_public_id(value, prefix=ORGANIZATION_ID_PREFIX)


def _parse_public_id(value: str, *, prefix: str) -> PublicId:
    try:
        return parse_prefixed_public_id(value, prefix=prefix)
    except ValueError as exc:
        msg = f"Invalid public identifier: {value}"
        raise ValueError(msg) from exc

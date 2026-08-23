"""Public identifier parsing dependencies."""

from typing import Annotated

from fastapi import Path

from app.api.errors import InvalidPublicIdError
from app.identity.public_ids import (
    format_organization_id as _format_organization_id,
    format_user_id as _format_user_id,
    ORGANIZATION_ID_PATTERN,
    parse_organization_id as _parse_organization_id,
    parse_user_id as _parse_user_id,
    USER_ID_PATTERN,
)
from app.public_ids import PublicId


UserIdPath = Annotated[
    str,
    Path(
        pattern=USER_ID_PATTERN,
        description="User identifier (format: usr_XXXXXXXXXXXXX)",
        examples=["usr_00001PZB4XJM0"],
    ),
]


def parse_user_id(value: str) -> PublicId:
    """Parse a user identifier using the package's canonical format."""
    try:
        return _parse_user_id(value)
    except ValueError as exc:
        raise InvalidPublicIdError from exc


def format_user_id(value: PublicId) -> str:
    """Format a user identifier using the package's canonical format."""
    return _format_user_id(value)


OrganizationIdPath = Annotated[
    str,
    Path(
        pattern=ORGANIZATION_ID_PATTERN,
        description="Organization identifier (format: org_XXXXXXXXXXXXX)",
        examples=["org_00001PZB4XJM0"],
    ),
]


def parse_organization_id(value: str) -> PublicId:
    """Parse an organization identifier using the package's canonical format."""
    try:
        return _parse_organization_id(value)
    except ValueError as exc:
        raise InvalidPublicIdError from exc


def format_organization_id(value: PublicId) -> str:
    """Format an organization identifier using the package's canonical format."""
    return _format_organization_id(value)

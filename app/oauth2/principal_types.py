"""OAuth2 bearer principal type claims."""

from enum import StrEnum


class PrincipalType(StrEnum):
    """Explicit OAuth2 bearer principal type."""

    USER = "user"
    CLIENT = "client"

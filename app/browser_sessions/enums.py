"""Authentication by session cookies enums."""

from enum import StrEnum


class LogoutScope(StrEnum):
    """Browser sessions selected by a logout request."""

    CURRENT = "current"
    OTHERS = "others"
    ALL = "all"


class CSRFTokenExposure(StrEnum):
    """Enum for CSRF token exposure methods."""

    HEADER = "header"
    COOKIE = "cookie"


class CSRFPattern(StrEnum):
    """Enum for CSRF policy pattern."""

    DOUBLE_SUBMIT = "double_submit"
    SYNCHRONIZER_TOKEN = "synchronizer_token"  # noqa: S105


class CookieSameSite(StrEnum):
    """Enum for Cookies Same Site values."""

    STRICT = "strict"
    LAX = "lax"
    NONE = "none"

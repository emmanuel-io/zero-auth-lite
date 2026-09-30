"""Authentication by session cookies enums."""

from enum import StrEnum


class LogoutScope(StrEnum):
    """Browser sessions selected by a logout request."""

    CURRENT = "current"
    OTHERS = "others"
    ALL = "all"


class BrowserSessionRevocationReason(StrEnum):
    """Stable reasons persisted when browser-session authority ends."""

    LOGOUT = "logout"
    LOGOUT_ALL = "logout_all"
    LOGOUT_OTHERS = "logout_others"
    USER_REVOKED = "user_revoked"
    USER_AUTH_CHANGED = "user_auth_changed"
    PASSWORD_CHANGED = "password_changed"  # noqa: S105
    EMAIL_CHANGED = "email_changed"
    EMAIL_VERIFIED = "email_verified"
    PASSWORD_RESET = "password_reset"  # noqa: S105
    INVITE_ACCEPTED = "invite_accepted"
    OPERATOR_REVOKED_USER_SESSIONS = "operator_revoked_user_sessions"
    ORGANIZATION_ADMIN_REVOKED_USER_SESSIONS = (
        "organization_admin_revoked_user_sessions"
    )
    ORGANIZATION_SESSIONS_REVOKED = "organization_sessions_revoked"
    SERVER_SESSIONS_REVOKED = "server_sessions_revoked"


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

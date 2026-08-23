"""Browser-session data transfer objects."""

from dataclasses import dataclass
from datetime import datetime, UTC
from logging import getLogger

from app.public_ids import PublicId


logger = getLogger(__name__)


def _assert_aware(value: datetime) -> None:
    """Require timezone-aware session timestamps."""
    if value.tzinfo is None or value.utcoffset() is None:
        logger.error("Session timestamps must be timezone-aware (UTC).")
        raise ValueError


@dataclass(frozen=True, slots=True)
class LoginResultDTO:
    """Browser-session transport values returned by a successful login.

    Attributes:
        session (str): The session cookie content.
        csrf (str): The CSRF cookie content.
    """

    session: str
    csrf: str


@dataclass(frozen=True, slots=True)
class SessionCreateDTO:
    """Input for creating a browser session."""

    stored_session_id: str
    user_id: int
    csrf: str
    absolute_expires_at: datetime
    expires_at: datetime
    ip_hash: str | None = None
    user_agent_hash: str | None = None

    def __post_init__(self) -> None:
        """Validate session expiry timestamps."""
        _assert_aware(self.absolute_expires_at)
        _assert_aware(self.expires_at)


@dataclass(frozen=True, slots=True)
class SessionReadDTO:
    """Stable browser-session state returned by services."""

    stored_session_id: str
    public_id: PublicId
    user_id: int
    csrf: str
    absolute_expires_at: datetime
    created_at: datetime
    expires_at: datetime
    ip_hash: str | None
    last_seen_at: datetime
    revoked_at: datetime | None
    revoked_reason: str | None
    updated_at: datetime
    user_agent_hash: str | None

    def __post_init__(self) -> None:
        """Validate all persisted session timestamps."""
        for value in (
            self.absolute_expires_at,
            self.created_at,
            self.expires_at,
            self.last_seen_at,
            self.updated_at,
        ):
            _assert_aware(value)
        if self.revoked_at is not None:
            _assert_aware(self.revoked_at)

    def is_active(self, *, now: datetime | None = None) -> bool:
        """Return whether the session is unrevoked and inside both expiries."""
        checked_at = now or datetime.now(UTC)
        _assert_aware(checked_at)
        return bool(
            self.revoked_at is None
            and self.expires_at > checked_at
            and self.absolute_expires_at > checked_at
        )


@dataclass(frozen=True, slots=True)
class SessionSlideResultDTO:
    """Session state plus whether browser transport must extend its expiry."""

    session: SessionReadDTO
    expiry_extended: bool

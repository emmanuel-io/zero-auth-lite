"""Serializable domain event base types."""

from datetime import datetime, UTC
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.core.specs import UUID_HEX_LENGTH, UUID_HEX_PATTERN


def _utc_now() -> datetime:
    """Return the current UTC timestamp for event metadata."""
    return datetime.now(UTC)


class BaseEvent(BaseModel):
    """Base class for application-level events.

    Events describe business facts intended to commit. They must stay JSON-serializable
    and must not carry ORM objects, sessions, raw tokens, or service instances.
    """

    model_config = ConfigDict(frozen=True)

    event_id: str = Field(
        default_factory=lambda: uuid4().hex,
        min_length=UUID_HEX_LENGTH,
        max_length=UUID_HEX_LENGTH,
        pattern=UUID_HEX_PATTERN,
    )
    event_type: str
    occurred_at: datetime = Field(default_factory=_utc_now)

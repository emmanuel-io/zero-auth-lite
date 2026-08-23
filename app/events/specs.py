"""Persistence and validation contracts for application events."""

from enum import StrEnum
from typing import Final


class OutboxProcessingResult(StrEnum):
    """Terminal outcomes recorded for a processed outbox event."""

    DELIVERED = "delivered"
    DISCARDED_EMAIL_DISABLED = "discarded_email_disabled"
    DISCARDED_TARGET_UNAVAILABLE = "discarded_target_unavailable"


class EventSpecs:
    """Shared application-event field limits."""

    EVENT_TYPE_LENGTH_MAX: Final[int] = 96
    PROCESSING_RESULT_LENGTH_MAX: Final[int] = max(
        len(result.value) for result in OutboxProcessingResult
    )

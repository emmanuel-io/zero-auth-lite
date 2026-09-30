"""Persistence contracts for durable authentication notifications."""

from enum import StrEnum
from typing import Final


class OutboxProcessingResult(StrEnum):
    """Terminal outcomes recorded for a processed outbox event."""

    DELIVERED = "delivered"
    DISCARDED_EMAIL_DISABLED = "discarded_email_disabled"
    DISCARDED_TARGET_UNAVAILABLE = "discarded_target_unavailable"
    FAILED_PERMANENT = "failed_permanent"


class NotificationSpecs:
    """Shared notification-outbox field limits."""

    EVENT_TYPE_LENGTH_MAX: Final[int] = 96
    PROCESSING_RESULT_LENGTH_MAX: Final[int] = max(
        len(result.value) for result in OutboxProcessingResult
    )

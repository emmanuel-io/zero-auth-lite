"""SQLAlchemy model for durable authentication-notification delivery."""

from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.logs.correlation import CORRELATION_ID_LENGTH
from app.core.specs import UUID_HEX_LENGTH
from app.db.base import Base
from app.db.mixins import CreatedAtMixin, UpdatedAtMixin
from app.notifications.specs import NotificationSpecs


class NotificationOutboxDB(Base, CreatedAtMixin, UpdatedAtMixin):
    """Notification event persisted in the transaction that produced it."""

    __tablename__ = "notification_outbox"
    __table_args__ = (
        CheckConstraint(
            "event_type IN "
            "('auth.password_reset_requested', "
            "'auth.account_verification_requested', "
            "'auth.email_change_requested', 'auth.invite_created')",
            name="event_type_valid",
        ),
        CheckConstraint(
            "processing_result IS NULL OR processing_result IN "
            "('delivered', 'discarded_email_disabled', "
            "'discarded_target_unavailable', 'failed_permanent')",
            name="processing_result_valid",
        ),
        CheckConstraint("attempt_count >= 0", name="attempt_count_nonnegative"),
        CheckConstraint(
            "(claimed_at IS NULL AND claimed_by IS NULL) OR "
            "(claimed_at IS NOT NULL AND claimed_by IS NOT NULL)",
            name="claim_pair",
        ),
        CheckConstraint(
            "(processed_at IS NULL AND processing_result IS NULL) OR "
            "(processed_at IS NOT NULL AND processing_result IS NOT NULL)",
            name="processing_pair",
        ),
        CheckConstraint(
            "processed_at IS NULL OR (claimed_at IS NULL AND claimed_by IS NULL)",
            name="processed_unclaimed",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(
        String(UUID_HEX_LENGTH), unique=True, nullable=False
    )
    event_type: Mapped[str] = mapped_column(
        String(NotificationSpecs.EVENT_TYPE_LENGTH_MAX), index=True, nullable=False
    )
    correlation_id: Mapped[str | None] = mapped_column(
        String(CORRELATION_ID_LENGTH), nullable=True
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, nullable=False
    )
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    claimed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True, nullable=True
    )
    claimed_by: Mapped[str | None] = mapped_column(
        String(UUID_HEX_LENGTH), nullable=True
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    processing_result: Mapped[str | None] = mapped_column(
        String(NotificationSpecs.PROCESSING_RESULT_LENGTH_MAX), nullable=True
    )
    processed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True, nullable=True
    )

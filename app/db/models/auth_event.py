"""SQLAlchemy model for durable application-event delivery."""

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.logs.correlation import CORRELATION_ID_LENGTH
from app.core.specs import UUID_HEX_LENGTH
from app.db.base import Base
from app.db.mixins import CreatedAtMixin, UpdatedAtMixin
from app.events.specs import EventSpecs


class AuthEventOutboxDB(Base, CreatedAtMixin, UpdatedAtMixin):
    """Notification event persisted in the transaction that produced it."""

    __tablename__ = "auth_event_outbox"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(
        String(UUID_HEX_LENGTH), unique=True, nullable=False
    )
    event_type: Mapped[str] = mapped_column(
        String(EventSpecs.EVENT_TYPE_LENGTH_MAX), index=True, nullable=False
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
        String(EventSpecs.PROCESSING_RESULT_LENGTH_MAX), nullable=True
    )
    processed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True, nullable=True
    )

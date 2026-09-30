"""SQLAlchemy models for single-use workflow tokens."""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.specs import SHA256_HEX_LENGTH
from app.db.base import Base
from app.db.mixins import CreatedAtMixin
from app.workflow_tokens.enums import WorkflowTokenPurpose
from app.workflow_tokens.specs import WorkflowTokenSpecs


class UserWorkflowTokenDB(Base, CreatedAtMixin):
    """Token used for user verification, invites, and password resets."""

    __tablename__ = "user_workflow_token"
    __table_args__ = (
        CheckConstraint(
            "purpose IN ('verify_email', 'email_change', 'invite', 'reset_password')",
            name="purpose_valid",
        ),
        CheckConstraint(
            "(source_event_id IS NULL AND source_event_occurred_at IS NULL "
            "AND derivation_key_id IS NULL) OR "
            "(source_event_id IS NOT NULL AND source_event_occurred_at IS NOT NULL "
            "AND derivation_key_id IS NOT NULL)",
            name="event_derivation_fields",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_email_id: Mapped[int] = mapped_column(
        ForeignKey("user_email.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    purpose: Mapped[WorkflowTokenPurpose] = mapped_column(
        String(WorkflowTokenSpecs.PURPOSE_LENGTH_MAX),
        index=True,
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(
        String(SHA256_HEX_LENGTH), unique=True, nullable=False
    )
    source_event_id: Mapped[str | None] = mapped_column(
        String(WorkflowTokenSpecs.SOURCE_EVENT_ID_LENGTH), unique=True, nullable=True
    )
    source_event_occurred_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True, nullable=True
    )
    derivation_key_id: Mapped[str | None] = mapped_column(
        String(WorkflowTokenSpecs.DERIVATION_KEY_ID_LENGTH_MAX), nullable=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
        nullable=False,
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        index=True,
        nullable=True,
    )

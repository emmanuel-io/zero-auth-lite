"""SQLAlchemy model for OAuth2 device authorization."""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, UpdatedAtMixin
from app.oauth2.specs import OAuth2Specs


class OAuth2DeviceAuthorizationDB(Base, CreatedAtMixin, UpdatedAtMixin):
    """Application-owned OAuth2 device authorization table."""

    __tablename__ = "oauth2_device_authorization"
    __table_args__ = (
        CheckConstraint(
            "(approved_at IS NULL AND denied_at IS NULL AND used_at IS NULL "
            "AND user_id IS NULL AND organization_id IS NULL) OR "
            "(approved_at IS NOT NULL AND denied_at IS NULL "
            "AND user_id IS NOT NULL AND organization_id IS NOT NULL) OR "
            "(approved_at IS NULL AND denied_at IS NOT NULL AND used_at IS NULL "
            "AND user_id IS NOT NULL AND organization_id IS NOT NULL)",
            name="decision_state_valid",
        ),
        Index("ix_oauth2_device_code_hash", "device_code_hash", unique=True),
        Index("ix_oauth2_user_code_hash", "user_code_hash", unique=True),
        Index("ix_oauth2_device_client_expires", "client_id", "expires_at"),
    )

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True, nullable=False
    )
    device_code_hash: Mapped[str] = mapped_column(
        String(OAuth2Specs.HASH_LENGTH), nullable=False
    )
    user_code_hash: Mapped[str] = mapped_column(
        String(OAuth2Specs.HASH_LENGTH), nullable=False
    )
    client_id: Mapped[str] = mapped_column(
        String(OAuth2Specs.CLIENT_ID_LENGTH_MAX),
        ForeignKey("oauth2_client.client_id", ondelete="CASCADE"),
        nullable=False,
    )
    scope: Mapped[str] = mapped_column(
        String(OAuth2Specs.SCOPE_LIST_LENGTH_MAX), nullable=False, default=""
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    last_polled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    denied_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("user.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    organization_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("organization.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

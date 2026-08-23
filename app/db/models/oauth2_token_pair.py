"""SQLAlchemy models for OAuth2 token families and refresh history."""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, UpdatedAtMixin
from app.oauth2.specs import OAuth2Specs


class OAuth2TokenPairDB(Base, CreatedAtMixin, UpdatedAtMixin):
    """Current access-token and optional refresh-token state for one session."""

    __tablename__ = "oauth2_token_pair"
    __table_args__ = (
        CheckConstraint(
            "(refresh_token_hash IS NULL AND refresh_expires_at IS NULL) OR "
            "(refresh_token_hash IS NOT NULL AND refresh_expires_at IS NOT NULL)",
            name="refresh_pair",
        ),
        Index("ix_oauth2_token_pair_refresh_expires", "refresh_expires_at"),
        Index("ix_oauth2_token_pair_access_expires", "access_expires_at"),
    )

    session_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("oauth2_session.id", ondelete="CASCADE"),
        primary_key=True,
    )
    access_token_hash: Mapped[str] = mapped_column(
        String(OAuth2Specs.HASH_LENGTH), unique=True, index=True
    )
    access_jti: Mapped[str] = mapped_column(
        String(OAuth2Specs.HASH_LENGTH), unique=True, index=True
    )
    refresh_token_hash: Mapped[str | None] = mapped_column(
        String(OAuth2Specs.HASH_LENGTH), unique=True, index=True, nullable=True
    )
    access_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    refresh_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class OAuth2RefreshTokenHistoryDB(Base, CreatedAtMixin):
    """Consumed refresh-token hashes retained for family-reuse detection."""

    __tablename__ = "oauth2_refresh_token_history"

    token_hash: Mapped[str] = mapped_column(
        String(OAuth2Specs.HASH_LENGTH), primary_key=True
    )
    session_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("oauth2_session.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

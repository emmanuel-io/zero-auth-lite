"""SQLAlchemy model for browser sessions."""

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.browser_sessions.specs import SessionSpecs
from app.core.specs import SHA256_HEX_LENGTH
from app.db.base import Base
from app.db.mixins import CreatedAtMixin, UpdatedAtMixin
from app.db.snowflake import generate_snowflake_id
from app.public_ids import PublicId


class BrowserSessionDB(Base, CreatedAtMixin, UpdatedAtMixin):
    """Application-owned browser session table."""

    __tablename__ = "browser_session"
    __table_args__ = (
        Index("ix_browser_session_user_expires", "user_id", "expires_at"),
        Index("ix_browser_session_user_last_seen", "user_id", "last_seen_at"),
    )

    id: Mapped[str] = mapped_column(String(SHA256_HEX_LENGTH), primary_key=True)
    public_id: Mapped[PublicId] = mapped_column(
        BigInteger,
        unique=True,
        index=True,
        nullable=False,
        default=generate_snowflake_id,
    )
    csrf: Mapped[str] = mapped_column(String(SessionSpecs.TOKEN_LENGTH), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, nullable=False
    )
    absolute_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, nullable=False
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True, nullable=True
    )
    revoked_reason: Mapped[str | None] = mapped_column(
        String(SessionSpecs.REVOCATION_REASON_LENGTH_MAX), nullable=True
    )
    ip_hash: Mapped[str | None] = mapped_column(
        String(SHA256_HEX_LENGTH), nullable=True
    )
    user_agent_hash: Mapped[str | None] = mapped_column(
        String(SHA256_HEX_LENGTH), nullable=True
    )
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("user.id", ondelete="CASCADE"), nullable=False
    )

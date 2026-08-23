"""SQLAlchemy model for OAuth2 grant and token-family sessions."""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, PublicIdMixin, UpdatedAtMixin
from app.oauth2.specs import OAuth2Specs


class OAuth2SessionDB(Base, PublicIdMixin, CreatedAtMixin, UpdatedAtMixin):
    """OAuth2 session for a user-backed or machine token family."""

    __tablename__ = "oauth2_session"
    __table_args__ = (
        CheckConstraint(
            "(user_id IS NULL AND organization_id IS NULL) OR "
            "(user_id IS NOT NULL AND organization_id IS NOT NULL)",
            name="principal_pair",
        ),
        Index("ix_oauth2_session_user_ended", "user_id", "ended_at"),
        Index(
            "ix_oauth2_session_organization_created", "organization_id", "created_at"
        ),
        Index(
            "ix_oauth2_session_user_organization_created",
            "user_id",
            "organization_id",
            "created_at",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True, nullable=False
    )
    user_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("user.id", ondelete="CASCADE"), nullable=True
    )
    organization_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("organization.id", ondelete="CASCADE"), nullable=True
    )
    client_id: Mapped[str] = mapped_column(
        String(OAuth2Specs.CLIENT_ID_LENGTH_MAX),
        ForeignKey("oauth2_client.client_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    grant_type: Mapped[str] = mapped_column(
        String(OAuth2Specs.GRANT_TYPE_LENGTH_MAX), nullable=False, index=True
    )
    scope: Mapped[str] = mapped_column(
        String(OAuth2Specs.SCOPE_LIST_LENGTH_MAX), nullable=False, default=""
    )
    ended_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )

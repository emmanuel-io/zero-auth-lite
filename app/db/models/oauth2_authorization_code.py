"""SQLAlchemy model for OAuth2 authorization codes."""

from datetime import datetime, UTC

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin
from app.oauth2.specs import OAuth2Specs


class OAuth2AuthorizationCodeDB(Base, CreatedAtMixin):
    """Application-owned OAuth2 authorization code table."""

    __tablename__ = "oauth2_authorization_code"
    __table_args__ = (
        Index("ix_oauth2_auth_code_hash", "code_hash", unique=True),
        Index("ix_oauth2_auth_code_client_expires", "client_id", "expires_at"),
    )

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True, nullable=False
    )
    code_hash: Mapped[str] = mapped_column(
        String(OAuth2Specs.HASH_LENGTH), nullable=False
    )
    client_id: Mapped[str] = mapped_column(
        String(OAuth2Specs.CLIENT_ID_LENGTH_MAX),
        ForeignKey("oauth2_client.client_id", ondelete="CASCADE"),
        nullable=False,
    )
    redirect_uri: Mapped[str] = mapped_column(
        String(OAuth2Specs.REDIRECT_URI_LENGTH_MAX), nullable=False
    )
    scope: Mapped[str] = mapped_column(
        String(OAuth2Specs.SCOPE_LIST_LENGTH_MAX), nullable=False, default=""
    )
    nonce: Mapped[str | None] = mapped_column(
        String(OAuth2Specs.NONCE_LENGTH_MAX), nullable=True, default=None
    )
    code_challenge: Mapped[str] = mapped_column(
        String(OAuth2Specs.CODE_CHALLENGE_LENGTH_MAX), nullable=False
    )
    code_challenge_method: Mapped[str] = mapped_column(
        String(OAuth2Specs.CODE_CHALLENGE_METHOD_LENGTH_MAX), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    authenticated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("organization.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

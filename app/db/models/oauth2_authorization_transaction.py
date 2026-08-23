"""SQLAlchemy model for server-side OAuth2 authorization transactions."""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin
from app.oauth2.specs import OAuth2Specs


class OAuth2AuthorizationTransactionDB(Base, CreatedAtMixin):
    """Server-side browser authorization transaction."""

    __tablename__ = "oauth2_authorization_transaction"
    __table_args__ = (
        CheckConstraint(
            "(user_id IS NULL AND organization_id IS NULL) OR "
            "(user_id IS NOT NULL AND organization_id IS NOT NULL)",
            name="principal_pair",
        ),
        CheckConstraint(
            "used_at IS NULL OR (user_id IS NOT NULL AND organization_id IS NOT NULL)",
            name="used_requires_principal",
        ),
        Index("ix_oauth2_auth_transaction_hash", "transaction_hash", unique=True),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    transaction_hash: Mapped[str] = mapped_column(
        String(OAuth2Specs.HASH_LENGTH), nullable=False
    )
    response_type: Mapped[str] = mapped_column(
        String(OAuth2Specs.RESPONSE_TYPE_LENGTH_MAX), nullable=False
    )
    client_id: Mapped[str] = mapped_column(
        String(OAuth2Specs.CLIENT_ID_LENGTH_MAX),
        ForeignKey("oauth2_client.client_id", ondelete="CASCADE"),
        nullable=False,
    )
    redirect_uri: Mapped[str] = mapped_column(
        String(OAuth2Specs.REDIRECT_URI_LENGTH_MAX), nullable=False
    )
    scope: Mapped[str | None] = mapped_column(
        String(OAuth2Specs.SCOPE_LIST_LENGTH_MAX), nullable=True
    )
    state: Mapped[str | None] = mapped_column(
        String(OAuth2Specs.STATE_LENGTH_MAX), nullable=True
    )
    nonce: Mapped[str | None] = mapped_column(
        String(OAuth2Specs.NONCE_LENGTH_MAX), nullable=True
    )
    code_challenge: Mapped[str] = mapped_column(
        String(OAuth2Specs.CODE_CHALLENGE_LENGTH_MAX), nullable=False
    )
    code_challenge_method: Mapped[str] = mapped_column(
        String(OAuth2Specs.CODE_CHALLENGE_METHOD_LENGTH_MAX), nullable=False
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
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

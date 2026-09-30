"""SQLAlchemy model for server-side OAuth2 authorization transactions."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin
from app.oauth2.specs import OAuth2Specs


class OAuth2AuthorizationTransactionDB(Base, CreatedAtMixin):
    """Server-side browser authorization transaction."""

    __tablename__ = "oauth2_authorization_transaction"
    __table_args__ = (
        CheckConstraint("response_type = 'code'", name="response_type_valid"),
        CheckConstraint(
            "code_challenge_method = 'S256'",
            name="code_challenge_method_valid",
        ),
        CheckConstraint(
            "(user_id IS NULL AND organization_id IS NULL) OR "
            "(user_id IS NOT NULL AND organization_id IS NOT NULL)",
            name="principal_pair",
        ),
        CheckConstraint(
            "used_at IS NULL OR (user_id IS NOT NULL AND organization_id IS NOT NULL)",
            name="used_requires_principal",
        ),
        Index("uq_oauth2_auth_transaction_hash", "transaction_hash", unique=True),
        Index(
            "ix_oauth2_authorization_transaction_client_id",
            "client_id",
        ),
        Index(
            "ix_oauth2_authorization_transaction_used_id",
            "id",
            sqlite_where=text("used_at IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    transaction_hash: Mapped[str] = mapped_column(
        String(OAuth2Specs.HASH_LENGTH), nullable=False
    )
    response_type: Mapped[str] = mapped_column(
        String(OAuth2Specs.RESPONSE_TYPE_LENGTH_MAX), nullable=False
    )
    client_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
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

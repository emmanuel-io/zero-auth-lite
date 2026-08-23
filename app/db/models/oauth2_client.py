"""SQLAlchemy models for OAuth2 clients and organization assignments."""

from sqlalchemy import CheckConstraint, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, UpdatedAtMixin
from app.oauth2.clients.access import OAUTH2_CLIENT_ORGANIZATION_ACCESS_LENGTH_MAX
from app.oauth2.specs import OAuth2Specs


class OAuth2ClientDB(Base, CreatedAtMixin, UpdatedAtMixin):
    """Application-owned global OAuth2 registered client table."""

    __tablename__ = "oauth2_client"
    __table_args__ = (CheckConstraint("length(trim(name)) > 0", name="name_not_blank"),)

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True, nullable=False
    )
    client_id: Mapped[str] = mapped_column(
        String(OAuth2Specs.CLIENT_ID_LENGTH_MAX), unique=True, nullable=False
    )
    client_secret: Mapped[str | None] = mapped_column(
        String(OAuth2Specs.CLIENT_SECRET_HASH_LENGTH_MAX), nullable=True
    )
    name: Mapped[str] = mapped_column(
        String(OAuth2Specs.CLIENT_NAME_LENGTH_MAX), nullable=False
    )
    grant_types: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    redirect_uris: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    is_confidential: Mapped[bool] = mapped_column(nullable=False, default=True)
    requires_consent: Mapped[bool] = mapped_column(nullable=False, default=True)
    is_active: Mapped[bool] = mapped_column(nullable=False, default=True)
    user_organization_access: Mapped[str] = mapped_column(
        String(OAUTH2_CLIENT_ORGANIZATION_ACCESS_LENGTH_MAX),
        nullable=False,
        default="unrestricted",
        server_default="unrestricted",
    )
    machine_organization_access: Mapped[str] = mapped_column(
        String(OAUTH2_CLIENT_ORGANIZATION_ACCESS_LENGTH_MAX),
        nullable=False,
        default="none",
        server_default="none",
    )


class OAuth2ClientUserOrganizationDB(Base, CreatedAtMixin):
    """Allowed user organization for a global OAuth2 client."""

    __tablename__ = "oauth2_client_user_organization"
    client_id: Mapped[int] = mapped_column(
        ForeignKey("oauth2_client.id", ondelete="CASCADE"),
        primary_key=True,
    )
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organization.id", ondelete="CASCADE"), primary_key=True, index=True
    )


class OAuth2ClientMachineOrganizationDB(Base, CreatedAtMixin):
    """Organization resource assignment for a global OAuth2 machine client."""

    __tablename__ = "oauth2_client_machine_organization"
    client_id: Mapped[int] = mapped_column(
        ForeignKey("oauth2_client.id", ondelete="CASCADE"),
        primary_key=True,
    )
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organization.id", ondelete="CASCADE"), primary_key=True, index=True
    )

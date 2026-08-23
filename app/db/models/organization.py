"""SQLAlchemy model for organizations.

Defines the `OrganizationDB` ORM model, which groups user memberships under one
logical authorization scope.
"""

from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, PublicIdMixin, UpdatedAtMixin
from app.identity.organizations.specs import OrganizationSpecs


if TYPE_CHECKING:
    from app.db.models.organization_membership import OrganizationMembershipDB


class OrganizationDB(Base, PublicIdMixin, CreatedAtMixin, UpdatedAtMixin):
    """SQLAlchemy model representing an organization."""

    __tablename__ = "organization"
    __table_args__ = (CheckConstraint("length(trim(name)) > 0", name="name_not_blank"),)

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )
    name: Mapped[str] = mapped_column(
        String(OrganizationSpecs.NAME_LENGTH_MAX),
        nullable=False,
        index=True,
    )

    memberships: Mapped[list["OrganizationMembershipDB"]] = relationship(
        "OrganizationMembershipDB",
        back_populates="organization",
        lazy="raise",
        passive_deletes="all",
    )

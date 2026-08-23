"""Persist a user's membership in one organization."""

from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, Enum, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.identity.users.enums import OrganizationUserRole


if TYPE_CHECKING:
    from app.db.models.organization import OrganizationDB
    from app.db.models.user import UserDB


class OrganizationMembershipDB(Base):
    """Associate one user with one organization and scoped role."""

    __tablename__ = "organization_membership"
    __table_args__ = (
        CheckConstraint("role IN ('member', 'admin')", name="role_valid"),
    )

    user_id: Mapped[int] = mapped_column(
        ForeignKey("user.id", ondelete="CASCADE"),
        primary_key=True,
    )
    organization_id: Mapped[int] = mapped_column(
        ForeignKey("organization.id", ondelete="RESTRICT"),
        index=True,
        nullable=False,
    )
    role: Mapped[OrganizationUserRole] = mapped_column(
        Enum(
            OrganizationUserRole,
            name="organization_user_role",
            native_enum=False,
            create_constraint=False,
            validate_strings=True,
            values_callable=lambda members: [member.value for member in members],
        ),
        nullable=False,
        default=OrganizationUserRole.MEMBER,
    )

    user: Mapped["UserDB"] = relationship(
        "UserDB",
        back_populates="organization_membership",
        lazy="raise",
    )
    organization: Mapped["OrganizationDB"] = relationship(
        "OrganizationDB",
        back_populates="memberships",
        lazy="raise",
    )

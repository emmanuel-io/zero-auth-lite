"""Persist users and their platform-scoped identity state."""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, PublicIdMixin, UpdatedAtMixin
from app.identity.users.enums import UserEmailStatus
from app.identity.users.specs import UserSpecs


if TYPE_CHECKING:
    from app.db.models.organization_membership import OrganizationMembershipDB


class UserDB(Base, PublicIdMixin, CreatedAtMixin, UpdatedAtMixin):
    """SQLAlchemy model representing an application user."""

    __tablename__ = "user"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )
    first_name: Mapped[str] = mapped_column(
        String(UserSpecs.FIRST_NAME_LENGTH_MAX),
        nullable=False,
        default="",
    )
    last_name: Mapped[str] = mapped_column(
        String(UserSpecs.LAST_NAME_LENGTH_MAX),
        nullable=False,
        default="",
    )
    hashed_password: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )
    is_operator: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    sessions_invalid_before: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    organization_membership: Mapped["OrganizationMembershipDB"] = relationship(
        "OrganizationMembershipDB",
        back_populates="user",
        uselist=False,
        lazy="raise",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    emails: Mapped[list["UserEmailDB"]] = relationship(
        "UserEmailDB",
        back_populates="user",
        lazy="raise",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def email_by_status(self, status: UserEmailStatus) -> "UserEmailDB | None":
        """Return the explicitly loaded email in one lifecycle state."""
        return next((email for email in self.emails if email.status == status), None)

    @property
    def current_email(self) -> "UserEmailDB":
        """Return the required current email from the loaded collection."""
        email = self.email_by_status(UserEmailStatus.CURRENT)
        if email is None:
            msg = f"User {self.id} has no current email."
            raise RuntimeError(msg)
        return email

    @property
    def pending_email_record(self) -> "UserEmailDB | None":
        """Return the optional pending email from the loaded collection."""
        return self.email_by_status(UserEmailStatus.PENDING)

    @property
    def email(self) -> str:
        """Project the current address for stable service and API DTOs."""
        return self.current_email.email

    @property
    def pending_email(self) -> str | None:
        """Project the pending address for stable service and API DTOs."""
        pending = self.pending_email_record
        return pending.email if pending is not None else None

    @property
    def email_verified(self) -> bool:
        """Return whether the current address has been verified."""
        return self.current_email.verified_at is not None


class UserEmailDB(Base, CreatedAtMixin, UpdatedAtMixin):
    """Persist one current, pending, or retired user email address."""

    __tablename__ = "user_email"
    __table_args__ = (
        CheckConstraint(
            "status IN ('current', 'pending', 'retired')",
            name="valid_status",
        ),
        CheckConstraint(
            "status != 'pending' OR (verified_at IS NULL AND retired_at IS NULL)",
            name="pending_state",
        ),
        CheckConstraint(
            "status != 'current' OR retired_at IS NULL",
            name="current_state",
        ),
        CheckConstraint(
            "status != 'retired' OR retired_at IS NOT NULL",
            name="retired_state",
        ),
        Index(
            "uq_user_email_current_user",
            "user_id",
            unique=True,
            sqlite_where=text("status = 'current'"),
        ),
        Index(
            "uq_user_email_pending_user",
            "user_id",
            unique=True,
            sqlite_where=text("status = 'pending'"),
        ),
        Index(
            "uq_user_email_active_normalized",
            "normalized_email",
            unique=True,
            sqlite_where=text("status IN ('current', 'pending')"),
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("user.id", ondelete="CASCADE"), index=True, nullable=False
    )
    email: Mapped[str] = mapped_column(
        String(UserSpecs.EMAIL_LENGTH_MAX), nullable=False
    )
    normalized_email: Mapped[str] = mapped_column(
        String(UserSpecs.EMAIL_LENGTH_MAX), nullable=False
    )
    status: Mapped[UserEmailStatus] = mapped_column(
        String(16), nullable=False, default=UserEmailStatus.CURRENT
    )
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    retired_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped[UserDB] = relationship("UserDB", back_populates="emails", lazy="raise")

"""Database model mixins for common patterns."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    DateTime,
    func,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column


class PublicIdMixin:
    """Adds a public identifier exposed through the API."""

    public_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        unique=True,
        index=True,
        nullable=False,
        default=uuid4,
    )


class CreatedAtMixin:
    """Adds an immutable UTC creation timestamp."""

    __abstract__ = True

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class UpdatedAtMixin:
    """Adds an auto-updated UTC modification timestamp."""

    __abstract__ = True

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

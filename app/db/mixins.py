"""Database model mixins for common patterns."""

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.snowflake import generate_snowflake_id
from app.public_ids import PublicId


class PublicIdMixin:
    """Adds a public identifier exposed through the API."""

    public_id: Mapped[PublicId] = mapped_column(
        BigInteger,
        unique=True,
        index=True,
        nullable=False,
        default=generate_snowflake_id,
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

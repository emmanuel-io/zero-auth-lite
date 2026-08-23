"""Database helper functions for SQLAlchemy ORM."""

from logging import getLogger
from typing import TYPE_CHECKING

from .errors import (
    CheckViolationError,
    ConstraintViolationError,
    ForeignKeyViolationError,
    NotNullViolationError,
    UniqueViolationError,
)


if TYPE_CHECKING:
    from sqlalchemy.exc import IntegrityError

    from app.errors import DataConflictError

logger = getLogger(__name__)


def map_integrity_error(e: "IntegrityError") -> "DataConflictError":
    """Map a SQLAlchemy IntegrityError to a specific application-level exception.

    The original SQLite message is logged but never copied into the public error.
    """
    msg = str(getattr(e, "orig", None))
    lowered = msg.lower()

    logger.warning("Integrity error caught", extra={"original_error": msg})

    if "unique constraint failed" in lowered:
        return UniqueViolationError(msg)
    if "foreign key constraint failed" in lowered:
        return ForeignKeyViolationError(msg)
    if "not null constraint failed" in lowered:
        return NotNullViolationError(msg)
    if "check constraint failed" in lowered:
        return CheckViolationError(msg)

    return ConstraintViolationError(msg)

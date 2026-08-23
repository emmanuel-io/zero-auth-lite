"""SQLAlchemy Declarative base bound to a stable naming convention for Alembic."""

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase


# Stable naming convention for deterministic Alembic diffs
NAMING_CONVENTION: "dict[str, str]" = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = MetaData(naming_convention=NAMING_CONVENTION)


class Base(DeclarativeBase):
    """Root declarative base with deterministic naming convention."""

    metadata = metadata

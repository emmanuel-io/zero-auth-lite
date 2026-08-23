"""Alembic environment for the canonical Zero Auth Lite server schema."""
# ruff: noqa: INP001

from __future__ import annotations

from logging.config import fileConfig
from typing import TYPE_CHECKING

from alembic import context
from app.db.base import Base
from app.db.engine import create_engine, sqlite_url
from app.settings.root import load_settings

from app.db import alembic as _server_alembic


if TYPE_CHECKING:
    from app.settings.root import Settings
    from sqlalchemy.engine import Connection


_ = _server_alembic

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _load_database_settings() -> Settings:
    """Load settings and ensure the canonical database directory exists."""
    settings = load_settings()
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    return settings


def _configure_database_url(settings: Settings) -> None:
    """Populate the Alembic config from canonical server settings."""
    database_url = sqlite_url(settings.db_path)
    config.set_main_option(
        "sqlalchemy.url",
        database_url.render_as_string(hide_password=False),
    )


def run_migrations_offline() -> None:
    """Run migrations without creating an Engine."""
    settings = _load_database_settings()
    _configure_database_url(settings)
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Run migrations using a configured synchronous connection."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations through the canonical configured SQLite engine."""
    settings = _load_database_settings()
    _configure_database_url(settings)
    connectable = create_engine(settings.db_path, echo=settings.db_echo)

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    import asyncio

    asyncio.run(run_migrations_online())

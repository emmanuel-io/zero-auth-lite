"""Lifespan context manager for the canonical FastAPI application."""

import os
from contextlib import asynccontextmanager
from logging import getLogger
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from fastapi import FastAPI

from app.bootstrap.lock import serialized_bootstrap
from app.bootstrap.operator import bootstrap_operator_user
from app.db.engine import create_engine, create_session_factory
from app.db.migrations import ensure_database_is_migrated
from app.db.snowflake import (
    acquire_snowflake_node_lease,
    configure_snowflake_generator,
    SnowflakeNodeLease,
    unconfigure_snowflake_generator,
)
from app.settings.state import get_settings_snapshot


@asynccontextmanager
async def lifespan(app: "FastAPI") -> "AsyncGenerator[None]":
    """Prepare shared database resources and bootstrap the first operator."""
    logger = getLogger(__name__)
    logger.info("FastAPI application %s starting.", app.title)

    settings = get_settings_snapshot(app)
    snowflake_lease: SnowflakeNodeLease | None = None
    snowflake_configured = False
    try:
        snowflake_lease = acquire_snowflake_node_lease(
            lock_directory=settings.runtime_dir / "snowflake",
            requested_node_id=settings.snowflake_node_id,
        )
        configure_snowflake_generator(snowflake_lease.node_id)
        snowflake_configured = True
        allocation_mode = "automatic" if snowflake_lease.automatic else "explicit"
        logger.info(
            "Snowflake node acquired pid=%s node_id=%s mode=%s",
            os.getpid(),
            snowflake_lease.node_id,
            allocation_mode,
        )
        app.state.core_engine = create_engine(
            settings.db_path,
            echo=settings.db_echo,
        )
        app.state.core_session_factory = create_session_factory(app.state.core_engine)

        await ensure_database_is_migrated(app.state.core_engine)

        with serialized_bootstrap(settings.runtime_dir / "bootstrap"):
            async with app.state.core_session_factory() as db_session:
                await bootstrap_operator_user(
                    db_session=db_session,
                    settings=settings.bootstrap,
                    password_hasher=app.state.password_hasher,
                )

        logger.info("FastAPI application %s started.", app.title)
        yield
    finally:
        logger.info("FastAPI application %s stopping.", app.title)
        if hasattr(app.state, "core_engine"):
            await app.state.core_engine.dispose()
        if snowflake_configured:
            unconfigure_snowflake_generator()
        if snowflake_lease is not None:
            snowflake_lease.release()
    logger.info("FastAPI application %s stopped.", app.title)

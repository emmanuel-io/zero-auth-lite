"""Tests for canonical SQLite engine configuration."""

import logging
from pathlib import Path

import pytest
from app.db.engine import create_engine
from sqlalchemy import text


pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_engine_logs_sql_without_bound_parameter_values(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Keep SQL diagnostics useful without exposing bound values."""
    secret = "credential-that-must-not-appear"  # noqa: S105
    engine = create_engine(tmp_path / "logging.db")
    caplog.set_level(logging.INFO, logger="sqlalchemy.engine")

    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT :secret"), {"secret": secret})
    finally:
        await engine.dispose()

    messages = "\n".join(record.getMessage() for record in caplog.records)
    assert "SELECT ?" in messages
    assert secret not in messages
    assert "SQL parameters hidden" in messages

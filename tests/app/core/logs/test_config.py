"""Tests for minimal logging configuration."""

import logging
from collections.abc import Iterator

import pytest
from app.core.logs.config import (
    configure_logging,
    LOG_FORMAT,
    QUIET_LIBRARY_LOG_LEVELS,
)
from app.settings.app import AppSettings
from asgi_correlation_id import CorrelationIdFilter
from pydantic import ValidationError


pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def restore_root_logging() -> Iterator[None]:
    """Restore root logging after each test mutates global logging state."""
    root_logger = logging.getLogger()
    aiosqlite_logger = logging.getLogger("aiosqlite")
    sqlalchemy_logger = logging.getLogger("sqlalchemy")
    sqlalchemy_engine_logger = logging.getLogger("sqlalchemy.engine")
    previous_handlers = list(root_logger.handlers)
    previous_level = root_logger.level
    previous_aiosqlite_level = aiosqlite_logger.level
    previous_sqlalchemy_level = sqlalchemy_logger.level
    previous_sqlalchemy_engine_level = sqlalchemy_engine_logger.level

    yield

    root_logger.handlers.clear()
    root_logger.handlers.extend(previous_handlers)
    root_logger.setLevel(previous_level)
    aiosqlite_logger.setLevel(previous_aiosqlite_level)
    sqlalchemy_logger.setLevel(previous_sqlalchemy_level)
    sqlalchemy_engine_logger.setLevel(previous_sqlalchemy_engine_level)


def test_settings_default_log_level_is_info() -> None:
    """Assert the default application log level is INFO."""
    settings = AppSettings()

    assert settings.log_level == "INFO"


def test_configured_formatter_includes_correlation_id() -> None:
    """Assert console logs include the request correlation ID field."""
    configure_logging("INFO")

    root_logger = logging.getLogger()
    handler = root_logger.handlers[0]

    assert LOG_FORMAT == (
        "%(asctime)s %(levelname)s [cid:%(correlation_id)s] %(name)s: %(message)s"
    )
    assert handler.formatter is not None
    record = logging.LogRecord(
        name="tests",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="request finished",
        args=(),
        exc_info=None,
    )
    record.__dict__["correlation_id"] = "abc123"

    assert "[cid:abc123]" in handler.formatter.format(record)
    assert any(
        isinstance(log_filter, CorrelationIdFilter) for log_filter in handler.filters
    )


def test_debug_log_level_sets_root_logger_to_debug() -> None:
    """Assert DEBUG configures the root logger to DEBUG."""
    configure_logging("DEBUG")

    assert logging.getLogger().level == logging.DEBUG
    assert logging.getLogger("aiosqlite").level == logging.WARNING
    assert logging.getLogger("sqlalchemy").level == logging.WARNING
    assert logging.getLogger("sqlalchemy.engine").level == logging.INFO
    assert QUIET_LIBRARY_LOG_LEVELS == {
        "aiosqlite": logging.WARNING,
        "sqlalchemy": logging.WARNING,
    }


def test_info_log_level_keeps_sql_queries_quiet() -> None:
    """Only expose SQL statements in the explicit DEBUG development mode."""
    configure_logging("INFO")

    assert logging.getLogger("sqlalchemy.engine").level == logging.WARNING


def test_settings_reject_invalid_log_level() -> None:
    """Assert invalid app log levels fail settings validation."""
    with pytest.raises(ValidationError, match="Input should be"):
        AppSettings(log_level="TRACE")


def test_configure_logging_can_be_called_repeatedly() -> None:
    """Assert repeated logging configuration keeps one console handler."""
    configure_logging("INFO")
    configure_logging("WARNING")

    root_logger = logging.getLogger()

    assert root_logger.level == logging.WARNING
    assert len(root_logger.handlers) == 1

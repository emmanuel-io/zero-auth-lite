"""Minimal console logging for the canonical application."""

import json
import logging
import sys
from typing import Any

from asgi_correlation_id import CorrelationIdFilter

from app.core.logs.correlation import CORRELATION_ID_LENGTH


# Single console log format used by every application process.
LOG_FORMAT = "%(asctime)s %(levelname)s [cid:%(correlation_id)s] %(name)s: %(message)s"

QUIET_LIBRARY_LOG_LEVELS = {
    "aiosqlite": logging.WARNING,
    "sqlalchemy": logging.WARNING,
}
"""Minimum levels for libraries whose DEBUG output obscures application flow."""

APPLICATION_LOG_FIELDS = (
    "context",
    "error_message",
    "exception_type",
    "original_error",
    "violations",
)
"""Explicit application fields that may be appended to console logs."""


class ApplicationLogFormatter(logging.Formatter):
    """Append allow-listed structured context as one-line JSON."""

    def format(self, record: logging.LogRecord) -> str:
        """Format the base record and any application-owned context fields."""
        message = super().format(record)
        context: dict[str, Any] = {
            field: getattr(record, field)
            for field in APPLICATION_LOG_FIELDS
            if hasattr(record, field)
        }
        if not context:
            return message
        serialized_context = json.dumps(
            context,
            default=str,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return f"{message} fields={serialized_context}"


def configure_logging(level: str) -> None:
    """Configure console logging from a standard level name."""
    numeric_level = logging.getLevelNamesMapping().get(level.strip().upper())
    if numeric_level is None:
        msg = f"Unsupported log level: {level}"
        raise ValueError(msg)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(numeric_level)
    handler.addFilter(
        CorrelationIdFilter(
            uuid_length=CORRELATION_ID_LENGTH,
            default_value="background",
        )
    )
    handler.setFormatter(ApplicationLogFormatter(LOG_FORMAT))

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(numeric_level)
    root_logger.addHandler(handler)

    for logger_name, library_level in QUIET_LIBRARY_LOG_LEVELS.items():
        logging.getLogger(logger_name).setLevel(library_level)

    sqlalchemy_engine_level = (
        logging.INFO if numeric_level <= logging.DEBUG else logging.WARNING
    )
    logging.getLogger("sqlalchemy.engine").setLevel(sqlalchemy_engine_level)

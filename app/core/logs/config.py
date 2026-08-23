"""Minimal console logging for the canonical application."""

import logging
import sys

from asgi_correlation_id import CorrelationIdFilter

from app.core.logs.correlation import CORRELATION_ID_LENGTH


LOG_FORMAT = "%(asctime)s %(levelname)s [cid:%(correlation_id)s] %(name)s: %(message)s"
"""Single console log format used by the example."""

QUIET_LIBRARY_LOG_LEVELS = {
    "aiosqlite": logging.WARNING,
    "sqlalchemy": logging.WARNING,
}
"""Minimum levels for libraries whose DEBUG output obscures application flow."""


def configure_logging(level: str) -> None:
    """Configure standard-library console logging.

    Args:
        level: Standard logging level name such as ``INFO`` or ``DEBUG``.
    """
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
    handler.setFormatter(logging.Formatter(LOG_FORMAT))

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

"""Tests for client-safe SQLite integrity-error translation."""

import json
import logging
import sqlite3

import pytest
from app.core.errors.handlers import app_error_handler
from app.db.errors import (
    CheckViolationError,
    ForeignKeyViolationError,
    NotNullViolationError,
    UniqueViolationError,
)
from app.db.helpers import map_integrity_error
from app.settings.app import AppSettings
from app.settings.root import Settings
from app.settings.state import set_settings_snapshot
from fastapi import FastAPI
from sqlalchemy.exc import IntegrityError
from starlette.requests import Request


pytestmark = pytest.mark.unit

CONSTRAINT_CASES = [
    (
        "UNIQUE constraint failed: users.normalized_email",
        UniqueViolationError,
        "unique_violation",
        "A value that must be unique is already in use.",
    ),
    (
        "CHECK constraint failed: ck_users_state",
        CheckViolationError,
        "check_violation",
        "A stored-data rule rejected the requested value.",
    ),
    (
        "FOREIGN KEY constraint failed",
        ForeignKeyViolationError,
        "foreign_key_violation",
        "A referenced object does not exist or is still in use.",
    ),
    (
        "NOT NULL constraint failed: users.email",
        NotNullViolationError,
        "not_null_violation",
        "A required stored value is missing.",
    ),
]


def _integrity_error(message: str) -> IntegrityError:
    return IntegrityError("statement", {}, sqlite3.IntegrityError(message))


def _request(environment: str) -> Request:
    app = FastAPI()
    settings = Settings().model_copy(
        update={"app": AppSettings(environment=environment)}
    )
    set_settings_snapshot(app, settings)
    return Request({"type": "http", "app": app})


@pytest.mark.parametrize(
    ("sqlite_message", "error_type", "detail_type", "detail_message"), CONSTRAINT_CASES
)
def test_map_integrity_error_preserves_safe_constraint_variant(
    sqlite_message: str,
    error_type: type[
        UniqueViolationError
        | CheckViolationError
        | ForeignKeyViolationError
        | NotNullViolationError
    ],
    detail_type: str,
    detail_message: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Keep the precise Python variant while exposing one common public code."""
    with caplog.at_level(logging.WARNING, logger="app.db.helpers"):
        error = map_integrity_error(_integrity_error(sqlite_message))

    assert isinstance(error, error_type)
    assert error.code == "DATA_CONFLICT"
    assert error.formatted_message == "The requested data conflicts with stored data."
    assert error.payload.model_dump(mode="json")["details"] == [
        {"location": [], "message": detail_message, "type": detail_type}
    ]
    assert any(
        getattr(record, "original_error", None) == sqlite_message
        for record in caplog.records
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("sqlite_message", "error_type", "detail_type", "detail_message"), CONSTRAINT_CASES
)
async def test_constraint_details_are_environment_sensitive(
    sqlite_message: str,
    error_type: type[
        UniqueViolationError
        | CheckViolationError
        | ForeignKeyViolationError
        | NotNullViolationError
    ],
    detail_type: str,
    detail_message: str,
) -> None:
    """Expose safe diagnostics in development and redact them in deployment."""
    error = map_integrity_error(_integrity_error(sqlite_message))

    development = await app_error_handler(_request("development"), error)
    deployment = await app_error_handler(_request("deployment"), error)

    expected_base = {
        "code": "DATA_CONFLICT",
        "message": "The requested data conflicts with stored data.",
    }
    development_body = bytes(development.body)
    deployment_body = bytes(deployment.body)
    assert json.loads(development_body) == expected_base | {
        "details": [{"location": [], "message": detail_message, "type": detail_type}]
    }
    assert json.loads(deployment_body) == expected_base | {"details": []}
    assert sqlite_message not in development_body.decode()
    assert sqlite_message not in deployment_body.decode()
    assert error_type is type(error)

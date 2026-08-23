"""Tests for application-error OpenAPI response generation."""

from typing import cast, ClassVar, TYPE_CHECKING

import pytest
from app.api.error_responses import app_error_responses
from app.core.errors.base import AppError
from app.core.errors.handlers import app_error_handler
from app.core.errors.responses import ErrorResponse
from app.db.errors import (
    CheckViolationError,
    DatabaseBusyError,
    UniqueViolationError,
)
from app.settings.root import Settings
from app.settings.state import set_settings_snapshot
from fastapi import FastAPI, status
from httpx import ASGITransport, AsyncClient


if TYPE_CHECKING:
    from starlette.types import ExceptionHandler


pytestmark = pytest.mark.unit


class BearerRequiredError(AppError):
    """Example bearer authentication error."""

    code = "BEARER_REQUIRED"
    message = "Bearer authentication is required."
    status = status.HTTP_401_UNAUTHORIZED
    headers: ClassVar[dict[str, str]] = {"WWW-Authenticate": "Bearer"}


class SessionRequiredError(AppError):
    """Example browser-session authentication error."""

    code = "SESSION_REQUIRED"
    message = "A browser session is required."
    status = status.HTTP_401_UNAUTHORIZED
    headers: ClassVar[dict[str, str]] = {"WWW-Authenticate": "Session"}


class MissingObjectError(AppError):
    """Example missing-object error."""

    code = "MISSING_OBJECT"
    message = "The object does not exist."
    status = status.HTTP_404_NOT_FOUND


def test_app_error_responses_groups_examples_and_headers_by_status() -> None:
    """Aggregate error examples and alternative challenges under one response."""
    responses = app_error_responses(
        BearerRequiredError,
        SessionRequiredError,
        MissingObjectError,
        descriptions={401: "Authentication is required."},
    )

    assert responses[401]["model"] is ErrorResponse
    assert responses[401]["description"] == "Authentication is required."
    assert responses[401]["content"]["application/json"]["examples"] == {
        "BEARER_REQUIRED": {
            "summary": "Bearer authentication is required.",
            "value": {
                "code": "BEARER_REQUIRED",
                "message": "Bearer authentication is required.",
                "details": [],
            },
        },
        "SESSION_REQUIRED": {
            "summary": "A browser session is required.",
            "value": {
                "code": "SESSION_REQUIRED",
                "message": "A browser session is required.",
                "details": [],
            },
        },
    }
    assert responses[401]["headers"]["WWW-Authenticate"]["schema"] == {
        "type": "string",
        "enum": ["Bearer", "Session"],
    }
    assert responses[404]["description"] == MissingObjectError.message

    bearer_response = app_error_responses(BearerRequiredError)[401]
    assert bearer_response["headers"]["WWW-Authenticate"]["schema"] == {
        "type": "string",
        "const": "Bearer",
    }

    retryable_response = app_error_responses(DatabaseBusyError)[503]
    assert retryable_response["headers"]["Retry-After"]["schema"] == {
        "type": "string",
        "const": "1",
    }


def test_app_error_responses_rejects_conflicting_codes() -> None:
    """Reject ambiguous examples sharing a status and stable code."""

    class ConflictingBearerError(BearerRequiredError):
        message = "Different message."

    with pytest.raises(ValueError, match="Conflicting documented payloads"):
        app_error_responses(BearerRequiredError, ConflictingBearerError)


def test_app_error_responses_documents_variants_with_one_public_code() -> None:
    """Use internal example keys for variants sharing a client contract."""
    examples = app_error_responses(UniqueViolationError, CheckViolationError)[409][
        "content"
    ]["application/json"]["examples"]

    assert set(examples) == {"DATA_CONFLICT_UNIQUE", "DATA_CONFLICT_CHECK"}
    assert {example["value"]["code"] for example in examples.values()} == {
        "DATA_CONFLICT"
    }
    assert {
        example["value"]["details"][0]["type"] for example in examples.values()
    } == {"unique_violation", "check_violation"}


def test_app_error_responses_rejects_unknown_description_status() -> None:
    """Reject route descriptions that cannot be attached to an error status."""
    with pytest.raises(ValueError, match="undocumented HTTP statuses"):
        app_error_responses(BearerRequiredError, descriptions={403: "Forbidden."})


@pytest.mark.asyncio
async def test_runtime_payload_matches_the_documented_openapi_example() -> None:
    """Keep the runtime payload and generated OpenAPI example identical."""
    app = FastAPI()
    set_settings_snapshot(app, Settings())
    app.add_exception_handler(
        BearerRequiredError,
        cast("ExceptionHandler", app_error_handler),
    )

    @app.get(
        "/protected",
        responses=app_error_responses(BearerRequiredError),
    )
    async def protected() -> None:
        raise BearerRequiredError

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/protected")

    documented = app.openapi()["paths"]["/protected"]["get"]["responses"]["401"]
    example = documented["content"]["application/json"]["examples"]["BEARER_REQUIRED"][
        "value"
    ]
    assert response.json() == example
    assert response.headers["www-authenticate"] == "Bearer"
    assert documented["headers"]["WWW-Authenticate"]["schema"] == {
        "type": "string",
        "const": "Bearer",
    }

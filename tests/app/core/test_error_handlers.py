"""Tests for canonical application error response shapes."""

import json
from typing import cast, ClassVar, TYPE_CHECKING

import pytest
from app.browser_sessions.errors import SessionInvalidError
from app.core.errors.base import AppError
from app.core.errors.handlers import (
    app_error_handler,
    http_error_handler,
    unexpected_error_handler,
    validation_error_handler,
)
from app.db.errors import DatabaseBusyError
from app.errors import UnauthorizedError
from app.oauth2.error_handler import oauth2_protocol_error_handler
from app.oauth2.errors import InvalidClientError, OAuth2ProtocolError
from app.settings.app import AppSettings
from app.settings.root import Settings
from app.settings.state import set_settings_snapshot
from fastapi import FastAPI, HTTPException, status
from fastapi.exceptions import RequestValidationError
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel
from starlette.requests import Request


if TYPE_CHECKING:
    from starlette.types import ExceptionHandler


pytestmark = pytest.mark.unit


class ExampleAppError(AppError):
    """Example formatted application error."""

    code = "EXAMPLE"
    message = "Example %s"
    status = status.HTTP_409_CONFLICT
    headers: ClassVar[dict[str, str]] = {"WWW-Authenticate": "Bearer"}


class ExamplePayload(BaseModel):
    """Request body used to trigger FastAPI validation."""

    name: str


def request(*, environment: str = "development") -> Request:
    """Return a minimal request for handler invocation."""
    app = FastAPI()
    settings = Settings().model_copy(
        update={"app": AppSettings(environment=environment)}
    )
    set_settings_snapshot(app, settings)
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "app": app,
        }
    )


@pytest.mark.asyncio
async def test_custom_error_handler_serializes_domain_error_detail() -> None:
    """Assert domain errors expose a stable code and safe detail."""
    response = await app_error_handler(request(), ExampleAppError("detail"))

    assert response.status_code == status.HTTP_409_CONFLICT
    assert json.loads(response.body) == {
        "code": "EXAMPLE",
        "message": "Example detail",
        "details": [],
    }
    assert str(ExampleAppError("detail")) == "[EXAMPLE] Example detail"


@pytest.mark.asyncio
async def test_custom_error_handler_preserves_domain_error_headers() -> None:
    """Assert authentication metadata reaches HTTP clients."""
    response = await app_error_handler(request(), ExampleAppError("detail"))

    assert response.headers["www-authenticate"] == "Bearer"
    response.headers["www-authenticate"] = "Changed"
    assert ExampleAppError.headers == {"WWW-Authenticate": "Bearer"}


def test_app_error_without_headers_uses_an_empty_mapping() -> None:
    """Keep header-free errors reusable without per-instance state."""
    assert AppError.headers == {}
    assert AppError().headers == {}


@pytest.mark.parametrize(
    ("error", "expected_headers"),
    [
        (AppError, {}),
        (UnauthorizedError, {"WWW-Authenticate": "Bearer"}),
        (SessionInvalidError, {"WWW-Authenticate": "Session"}),
        (DatabaseBusyError, {"Retry-After": "1"}),
    ],
)
def test_app_error_classes_own_their_static_headers(
    error: type[AppError], expected_headers: dict[str, str]
) -> None:
    """Keep each application's response-header policy on its error class."""
    assert error.headers == expected_headers


@pytest.mark.asyncio
async def test_http_exception_uses_application_error_shape() -> None:
    """Assert plain HTTPException responses use the application envelope."""
    app = FastAPI()
    app.add_exception_handler(
        HTTPException,
        cast("ExceptionHandler", http_error_handler),
    )

    @app.get("/protected")
    async def protected() -> None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="not_authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/protected")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json() == {
        "code": "HTTP_401",
        "message": "not_authenticated",
        "details": [],
    }


@pytest.mark.asyncio
async def test_fastapi_validation_error_uses_application_error_shape() -> None:
    """Assert request validation errors use the application envelope."""
    app = FastAPI()
    app.add_exception_handler(
        RequestValidationError,
        cast("ExceptionHandler", validation_error_handler),
    )

    @app.post("/payload")
    async def payload_endpoint(payload: ExamplePayload) -> ExamplePayload:
        return payload

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.post("/payload", json={})

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert response.json() == {
        "code": "VALIDATION",
        "message": "Request validation failed.",
        "details": [
            {
                "location": ["body", "name"],
                "message": "Field required",
                "type": "missing",
            }
        ],
    }


@pytest.mark.asyncio
async def test_validation_details_remain_available_in_deployment() -> None:
    """Keep actionable request diagnostics outside persistence redaction."""
    app = FastAPI()
    settings = Settings().model_copy(
        update={"app": AppSettings(environment="deployment")}
    )
    set_settings_snapshot(app, settings)
    app.add_exception_handler(
        RequestValidationError,
        cast("ExceptionHandler", validation_error_handler),
    )

    @app.post("/payload")
    async def payload_endpoint(payload: ExamplePayload) -> ExamplePayload:
        return payload

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.post("/payload", json={})

    assert response.json()["details"] == [
        {
            "location": ["body", "name"],
            "message": "Field required",
            "type": "missing",
        }
    ]


@pytest.mark.asyncio
async def test_unexpected_error_uses_the_safe_internal_error_shape() -> None:
    """Keep unexpected exception details out of the client response."""
    error = RuntimeError("sensitive internal detail")
    response = await unexpected_error_handler(request(), error)

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert json.loads(response.body) == {
        "code": "INTERNAL_ERROR",
        "message": "Internal server error.",
        "details": [],
    }


@pytest.mark.asyncio
async def test_oauth2_protocol_error_keeps_rfc_error_shape() -> None:
    """Assert OAuth2 protocol errors are not converted to FastAPI detail."""
    response = await oauth2_protocol_error_handler(
        request(),
        OAuth2ProtocolError(
            error="invalid_grant",
            error_description="Authorization code expired",
            status_code=status.HTTP_400_BAD_REQUEST,
        ),
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert json.loads(response.body) == {
        "error": "invalid_grant",
        "error_description": "Authorization code expired",
    }


@pytest.mark.asyncio
async def test_oauth2_protocol_error_keeps_dynamic_challenge_headers() -> None:
    """Keep OAuth2 client challenges outside static AppError headers."""
    response = await oauth2_protocol_error_handler(
        request(),
        InvalidClientError(challenge_basic=True),
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.headers["www-authenticate"] == 'Basic realm="oauth2/token"'
    assert json.loads(response.body) == {"error": "invalid_client"}

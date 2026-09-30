"""Tests for application-level OpenAPI composition."""

import pytest
from app.core.openapi import REQUEST_ID_HEADER
from app.main import create_app
from app.settings.root import Settings
from fastapi import FastAPI


pytestmark = pytest.mark.unit


@pytest.fixture(scope="module")
def app() -> FastAPI:
    """Build the canonical schema without starting the application lifespan."""
    return create_app(Settings())


def test_openapi_documents_request_id_on_every_response(app: FastAPI) -> None:
    """Expose the correlation identifier returned by the global middleware."""
    for path_item in app.openapi()["paths"].values():
        for operation in path_item.values():
            if not isinstance(operation, dict):
                continue
            for response in operation.get("responses", {}).values():
                assert (
                    response["headers"]["X-Request-ID"]
                    == REQUEST_ID_HEADER["X-Request-ID"]
                )

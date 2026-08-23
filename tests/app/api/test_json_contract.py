"""Global OpenAPI invariants for application JSON contracts."""

from typing import Any

import pytest
from app.main import create_app
from app.public_ids import PUBLIC_ID_PAYLOAD_PATTERN
from app.settings.root import Settings
from app.web.settings import AuthenticationUIMode, UISettings
from fastapi import FastAPI


pytestmark = pytest.mark.unit

HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete"})
DOCUMENTED_JSON_EXTENSION_MODELS: frozenset[str] = frozenset()
EXTERNAL_LOGIN_URL = "https://frontend.test/login"


@pytest.fixture(scope="module")
def contract_app() -> FastAPI:
    """Build the canonical app without running database-backed lifespan setup."""
    return create_app(
        Settings(
            ui=UISettings(
                authentication=AuthenticationUIMode.EXTERNAL,
                external_login_url=EXTERNAL_LOGIN_URL,
            ),
        )
    )


def _referenced_schema_name(body_schema: dict[str, Any]) -> str:
    """Return the component name for one typed JSON request body."""
    reference = body_schema.get("$ref")
    assert isinstance(reference, str), "JSON request bodies must use typed schemas"
    return reference.rsplit("/", 1)[-1]


def test_non_protocol_json_requests_reject_unknown_properties(
    contract_app: FastAPI,
) -> None:
    """Keep every application JSON request strict unless explicitly extended."""
    openapi = contract_app.openapi()
    schemas = openapi["components"]["schemas"]
    checked_models: set[str] = set()

    for path_item in openapi["paths"].values():
        for method, operation in path_item.items():
            if method not in HTTP_METHODS:
                continue
            json_content = (
                operation.get("requestBody", {})
                .get("content", {})
                .get("application/json")
            )
            if json_content is None:
                continue
            model_name = _referenced_schema_name(json_content["schema"])
            checked_models.add(model_name)
            if model_name in DOCUMENTED_JSON_EXTENSION_MODELS:
                continue
            assert schemas[model_name].get("additionalProperties") is False, (
                f"{model_name} silently accepts unknown JSON properties"
            )

    assert checked_models


def test_openapi_never_exposes_public_id_vocabulary(contract_app: FastAPI) -> None:
    """Keep the persistence distinction out of every HTTP contract."""

    def contains_public_id(value: object) -> bool:
        if isinstance(value, dict):
            return any(
                "public_id" in str(key).lower() or contains_public_id(item)
                for key, item in value.items()
            )
        if isinstance(value, list):
            return any(contains_public_id(item) for item in value)
        return isinstance(value, str) and "public_id" in value.lower()

    assert not contains_public_id(contract_app.openapi())


def test_openapi_documents_canonical_public_id_payloads(
    contract_app: FastAPI,
) -> None:
    """Document public IDs with the canonical prefixed Base32 encoding."""
    openapi = contract_app.openapi()
    serialized = str(openapi)

    assert PUBLIC_ID_PAYLOAD_PATTERN in serialized
    assert "[0-9]{19}" not in serialized
    assert "0001900000004123456" not in serialized


def test_application_validation_errors_use_the_shared_error_response(
    contract_app: FastAPI,
) -> None:
    """Document application 422 responses with the runtime error envelope."""
    openapi = contract_app.openapi()
    assert set(openapi["components"]["schemas"]["ErrorResponse"]["properties"]) == {
        "code",
        "message",
        "details",
    }
    assert set(openapi["components"]["schemas"]["ErrorDetail"]["properties"]) == {
        "location",
        "message",
        "type",
    }

    for path, path_item in openapi["paths"].items():
        if not path.startswith("/api/"):
            continue
        for method, operation in path_item.items():
            if method not in HTTP_METHODS or "422" not in operation["responses"]:
                continue
            schema = operation["responses"]["422"]["content"]["application/json"][
                "schema"
            ]
            assert schema == {"$ref": "#/components/schemas/ErrorResponse"}
            example = operation["responses"]["422"]["content"]["application/json"][
                "examples"
            ]["VALIDATION"]["value"]
            assert example["code"] == "VALIDATION"
            assert example["details"]


def test_command_routes_document_empty_success_responses(
    contract_app: FastAPI,
) -> None:
    """Document commands without result data as 204 responses without bodies."""
    commands = {
        ("/api/v1/sessions/login", "post"),
        ("/api/v1/sessions/logout", "post"),
        ("/api/v1/auth/email/verify/request", "post"),
        ("/api/v1/auth/email/verify/confirm", "post"),
        ("/api/v1/auth/email/change/confirm", "post"),
        ("/api/v1/auth/password/forgot", "post"),
        ("/api/v1/auth/password/reset", "post"),
        ("/api/v1/auth/invite/accept", "post"),
        ("/api/v1/organization/users/{user_id}/invitation", "post"),
        ("/api/v1/admin/users/{user_id}/invitation", "post"),
        ("/api/v1/me/sessions/{session_id}", "delete"),
        ("/api/v1/me/authorizations/{authorization_id}", "delete"),
    }
    paths = contract_app.openapi()["paths"]

    for path, method in commands:
        responses = paths[path][method]["responses"]
        assert "200" not in responses
        assert "content" not in responses["204"]

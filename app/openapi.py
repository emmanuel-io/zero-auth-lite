"""OpenAPI composition for the canonical Zero Auth Lite application."""

from typing import Any

from fastapi import FastAPI

from app.core.openapi import (
    document_request_id_response_header,
    document_validation_error_response,
)
from app.oauth2.openapi import (
    configure_oauth2_schema,
    configure_protocol_operation,
)
from app.security.openapi import configure_application_api_security
from app.settings.state import get_settings_snapshot


def _operations(schema: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the operations contained in one generated OpenAPI schema."""
    operations: list[dict[str, Any]] = []
    for path_item in schema.get("paths", {}).values():
        if not isinstance(path_item, dict):
            continue
        operations.extend(
            operation for operation in path_item.values() if isinstance(operation, dict)
        )
    return operations


def configure_openapi(app: FastAPI) -> None:
    """Compose generic, application-security, and OAuth2 OpenAPI policies."""
    default_openapi = app.openapi

    def application_openapi() -> dict[str, Any]:
        schema = default_openapi()
        for operation in _operations(schema):
            if not configure_protocol_operation(operation):
                document_validation_error_response(operation)

        settings = get_settings_snapshot(app)
        configure_oauth2_schema(schema, settings)
        configure_application_api_security(schema, settings)
        document_request_id_response_header(schema)
        return schema

    app.openapi = application_openapi  # type: ignore[method-assign]  # ty: ignore[invalid-assignment]

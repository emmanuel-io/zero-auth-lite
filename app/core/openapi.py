"""Shared OpenAPI response contracts for the canonical server."""

from typing import Any

from app.core.errors.responses import ErrorDetail, ErrorResponse


REQUEST_ID_HEADER = {
    "X-Request-ID": {
        "description": "Identifier for tracing this request.",
        "schema": {"type": "string"},
    }
}


def document_validation_error_response(operation: dict[str, Any]) -> None:
    """Replace FastAPI's generated 422 body with the application error envelope."""
    response = operation.get("responses", {}).get("422")
    if not isinstance(response, dict):
        return
    response["description"] = "Request validation failed."
    response["content"] = {
        "application/json": {
            "schema": {"$ref": "#/components/schemas/ErrorResponse"},
            "examples": {
                "VALIDATION": {
                    "summary": "Request validation failed.",
                    "value": ErrorResponse(
                        code="VALIDATION",
                        message="Request validation failed.",
                        details=[
                            ErrorDetail(
                                location=["body", "field"],
                                message="Field required",
                                type="missing",
                            )
                        ],
                    ).model_dump(mode="json"),
                }
            },
        }
    }


def document_request_id_response_header(schema: dict[str, Any]) -> None:
    """Document the correlation header added to every HTTP response."""
    for path_item in schema.get("paths", {}).values():
        if not isinstance(path_item, dict):
            continue
        for operation in path_item.values():
            if not isinstance(operation, dict):
                continue
            for response in operation.get("responses", {}).values():
                if not isinstance(response, dict) or "$ref" in response:
                    continue
                response.setdefault("headers", {}).update(REQUEST_ID_HEADER)

"""OpenAPI adapters for application error classes."""

from collections import defaultdict
from collections.abc import Mapping
from typing import Any

from app.api.schemas import OpenAPIResponses
from app.core.errors.base import AppError
from app.core.errors.responses import ErrorResponse


def _documented_headers(
    errors: list[type[AppError]],
) -> dict[str, dict[str, object]]:
    """Build OpenAPI header declarations from grouped application errors."""
    names: dict[str, str] = {}
    values: dict[str, set[str]] = defaultdict(set)
    for error in errors:
        for name, value in error.headers.items():
            normalized_name = name.casefold()
            names.setdefault(normalized_name, name)
            values[normalized_name].add(value)

    documented: dict[str, dict[str, object]] = {}
    for normalized_name, header_values in values.items():
        ordered_values = sorted(header_values)
        schema: dict[str, object] = {"type": "string"}
        if len(ordered_values) == 1:
            schema["const"] = ordered_values[0]
        else:
            schema["enum"] = ordered_values
        documented[names[normalized_name]] = {
            "description": "Header returned with this application error.",
            "schema": schema,
        }
    return documented


def app_error_responses(
    *errors: type[AppError],
    descriptions: Mapping[int, str] | None = None,
) -> OpenAPIResponses:
    """Build FastAPI response documentation from application error classes."""
    grouped: dict[int, list[type[AppError]]] = defaultdict(list)
    examples_by_key: dict[tuple[int, str], dict[str, Any]] = {}
    for error in errors:
        payload = error.documented_payload().model_dump(mode="json")
        example_key = error.documented_example_key()
        key = (error.status, example_key)
        existing = examples_by_key.get(key)
        if existing is not None and existing != payload:
            msg = (
                f"Conflicting documented payloads for HTTP {error.status} "
                f"and example key {example_key}."
            )
            raise ValueError(msg)
        if existing is None:
            examples_by_key[key] = payload
        grouped[error.status].append(error)

    response_descriptions = dict(descriptions or {})
    unknown_statuses = set(response_descriptions) - set(grouped)
    if unknown_statuses:
        statuses = ", ".join(str(value) for value in sorted(unknown_statuses))
        msg = f"Descriptions provided for undocumented HTTP statuses: {statuses}."
        raise ValueError(msg)

    responses: OpenAPIResponses = {}
    for status_code, grouped_errors in sorted(grouped.items()):
        examples: dict[str, dict[str, Any]] = {}
        for error in grouped_errors:
            examples.setdefault(
                error.documented_example_key(),
                {
                    "summary": error.message,
                    "value": examples_by_key[
                        (status_code, error.documented_example_key())
                    ],
                },
            )
        response: dict[str, Any] = {
            "description": response_descriptions.get(
                status_code,
                grouped_errors[0].message
                if len(grouped_errors) == 1
                else "One of the documented application errors occurred.",
            ),
            "model": ErrorResponse,
            "content": {"application/json": {"examples": examples}},
        }
        headers = _documented_headers(grouped_errors)
        if headers:
            response["headers"] = headers
        responses[status_code] = response
    return responses

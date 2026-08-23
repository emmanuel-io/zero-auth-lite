"""Shared schemas for API route responses."""

from typing import Annotated, Any, TypeVar

from pydantic import BaseModel, ConfigDict, Field


T = TypeVar("T")
type OpenAPIResponses = dict[int | str, dict[str, Any]]
DEFAULT_PAGE_LIMIT_MAX = 100


def reject_explicit_nulls(value: object) -> object:
    """Keep omission as the only no-op signal for an HTTP PATCH."""
    if not isinstance(value, dict):
        return value
    null_fields = sorted(key for key, item in value.items() if item is None)
    if null_fields:
        fields = ", ".join(null_fields)
        msg = f"Explicit null is not allowed for: {fields}"
        raise ValueError(msg)
    return value


class PaginatedResponse[T](BaseModel):
    """Encapsulates paginated items and their pagination metadata."""

    model_config = ConfigDict(from_attributes=True)

    items: list[T] = Field(description="List of items in the current page")

    offset: Annotated[
        int | None,
        Field(ge=0, description="Offset used in the query"),
    ] = None
    limit: Annotated[
        int | None,
        Field(
            ge=1,
            le=DEFAULT_PAGE_LIMIT_MAX,
            description="Limit used in the query",
        ),
    ] = None
    total: Annotated[int, Field(ge=0, description="Total number of available items")]

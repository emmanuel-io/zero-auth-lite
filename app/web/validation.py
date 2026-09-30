"""Validation helpers for server-rendered form adapters."""

from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ValidationError


def validated_model[ModelT: BaseModel](
    model: type[ModelT], /, **values: object
) -> ModelT:
    """Build a service DTO and expose failures as request validation errors."""
    try:
        return model.model_validate(values)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc

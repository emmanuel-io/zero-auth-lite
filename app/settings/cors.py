"""CORS settings."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

from app.settings.defaults import LOCAL_ORIGINS
from app.settings.origins import normalize_http_origin


class CorsSettings(BaseModel):
    """CORS Middleware settings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed_origins: tuple[str, ...] = LOCAL_ORIGINS
    allow_credentials: bool = True
    allow_methods: tuple[
        Literal["*", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"],
        ...,
    ] = ("*",)
    allow_headers: tuple[str, ...] = ("*",)
    expose_headers: tuple[str, ...] = ("X-CSRF-Token", "X-Request-Id")

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def normalize_allowed_origins(cls, value: object) -> object:
        """Store allowed CORS origins in their canonical form."""
        if not isinstance(value, (list, tuple, set, frozenset)):
            return value
        return tuple(
            normalize_http_origin(name="allowed_origins", value=origin)
            if isinstance(origin, str)
            else origin
            for origin in value
        )

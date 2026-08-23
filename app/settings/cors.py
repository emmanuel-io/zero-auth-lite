"""CORS settings."""

from typing import Literal

from pydantic import BaseModel, ConfigDict

from app.settings.defaults import LOCAL_ORIGINS


class CorsSettings(BaseModel):
    """CORS Middleware settings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = True
    allowed_origins: tuple[str, ...] = LOCAL_ORIGINS
    allow_credentials: bool = True
    allow_methods: tuple[
        Literal["*", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"],
        ...,
    ] = ("*",)
    allow_headers: tuple[str, ...] = ("*",)
    expose_headers: tuple[str, ...] = ("X-CSRF-Token", "X-Request-Id")

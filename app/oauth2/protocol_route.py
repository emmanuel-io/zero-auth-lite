"""FastAPI route behavior specific to OAuth2 protocol endpoints."""

from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute

from app.db.errors import DatabaseBusyError
from app.oauth2.errors import OAuth2ProtocolError


PROTOCOL_OPENAPI_MARKER = "x-zero-auth-lite-oauth2-protocol"
"""OpenAPI marker for routes using OAuth2 protocol error semantics."""


class OAuth2ProtocolRoute(APIRoute):
    """Translate transport and availability failures into protocol errors."""

    def get_route_handler(
        self,
    ) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        """Wrap FastAPI validation without changing typed request extraction."""
        self.openapi_extra = {
            **(self.openapi_extra or {}),
            PROTOCOL_OPENAPI_MARKER: True,
        }
        original_handler = super().get_route_handler()

        async def protocol_route_handler(request: Request) -> Response:
            try:
                return await original_handler(request)
            except RequestValidationError as exc:
                error = "invalid_request"
                if any(
                    tuple(item.get("loc", ()))[-1:] == ("grant_type",)
                    and item.get("type") in {"enum", "literal_error"}
                    for item in exc.errors()
                ):
                    error = "unsupported_grant_type"
                raise OAuth2ProtocolError(error=error) from exc
            except DatabaseBusyError as exc:
                raise OAuth2ProtocolError(
                    error="temporarily_unavailable",
                    status_code=exc.status,
                    headers=exc.headers,
                ) from exc

        return protocol_route_handler

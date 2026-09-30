"""FastAPI route behavior specific to OAuth2 protocol endpoints."""

from collections.abc import Callable, Coroutine
from logging import getLogger
from typing import Any

from fastapi import Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute

from app.core.errors.base import AppError
from app.db.errors import DatabaseBusyError
from app.oauth2.error_codes import OAuth2ErrorCode
from app.oauth2.errors import OAuth2ProtocolError


logger = getLogger(__name__)


# Marks OpenAPI operations that use OAuth2 protocol error semantics.
PROTOCOL_OPENAPI_MARKER = "x-zero-auth-lite-oauth2-protocol"


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
                error = OAuth2ErrorCode.INVALID_REQUEST
                if any(
                    tuple(item.get("loc", ()))[-1:] == ("grant_type",)
                    and item.get("type") in {"enum", "literal_error"}
                    for item in exc.errors()
                ):
                    error = OAuth2ErrorCode.UNSUPPORTED_GRANT_TYPE
                raise OAuth2ProtocolError(error=error) from exc
            except DatabaseBusyError as exc:
                raise OAuth2ProtocolError(
                    error=OAuth2ErrorCode.TEMPORARILY_UNAVAILABLE,
                    status_code=exc.status,
                    headers=exc.headers,
                ) from exc
            except OAuth2ProtocolError:
                raise
            except AppError:
                raise
            except Exception as exc:
                logger.exception(
                    "Unexpected OAuth2 protocol route failure",
                    extra={"exception_type": type(exc).__name__},
                )
                raise OAuth2ProtocolError(
                    error=OAuth2ErrorCode.SERVER_ERROR,
                    status_code=500,
                ) from exc

        return protocol_route_handler

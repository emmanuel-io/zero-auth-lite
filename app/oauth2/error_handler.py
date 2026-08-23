"""HTTP exception handlers for OAuth2 protocol errors."""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse


if TYPE_CHECKING:
    from starlette.requests import Request

    from app.oauth2.errors import OAuth2ProtocolError


async def oauth2_protocol_error_handler(
    request: Request,  # noqa: ARG001
    exc: OAuth2ProtocolError,
) -> JSONResponse:
    """Serialize OAuth2 protocol errors without the application error envelope.

    Args:
        request: Incoming Starlette request.
        exc: OAuth2 protocol exception raised by the domain or router layer.

    Returns:
        JSONResponse: RFC-style OAuth2 error response.
    """
    content: dict[str, Any] = {"error": exc.error}
    if exc.error_description is not None:
        content["error_description"] = exc.error_description
    if exc.error_uri is not None:
        content["error_uri"] = exc.error_uri
    headers = dict(exc.headers)
    headers.setdefault("Cache-Control", "no-store")
    headers.setdefault("Pragma", "no-cache")
    return JSONResponse(
        status_code=exc.status_code,
        content=jsonable_encoder(content),
        headers=headers,
    )

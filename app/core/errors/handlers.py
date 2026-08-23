"""FastAPI handlers for canonical application error responses."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from logging import getLogger
from typing import Any, cast, TYPE_CHECKING

from fastapi import Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from app.core.errors.responses import ErrorDetail, ErrorResponse
from app.settings.state import get_settings_snapshot


if TYPE_CHECKING:
    from fastapi.exceptions import RequestValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    from app.core.errors.base import AppError


logger = getLogger(__name__)


def _log_http_error(
    *,
    message: str,
    context: dict[str, Any],
    status_code: int,
) -> None:
    """Log expected HTTP errors at a severity matching their status code.

    Args:
        message: Human-readable error message.
        context: Structured error context.
        status_code: HTTP status code on the exception.
    """
    if status_code >= status.HTTP_500_INTERNAL_SERVER_ERROR:
        logger.error("http_error", extra={"error_message": message, "context": context})
        return
    logger.warning("http_error", extra={"error_message": message, "context": context})


def _http_error_payload(
    *,
    status_code: int,
    detail_any: object,
) -> ErrorResponse:
    """Build a client-safe payload for expected HTTP exceptions.

    Args:
        status_code: HTTP status code on the exception.
        detail_any: Raw exception detail.

    Returns:
        ErrorResponse: Serialized error response.
    """
    if status_code >= status.HTTP_500_INTERNAL_SERVER_ERROR:
        return ErrorResponse(
            code="INTERNAL_ERROR",
            message="Internal server error.",
            details=[],
        )
    message = detail_any if isinstance(detail_any, str) else "HTTP error"
    return ErrorResponse(
        code=f"HTTP_{status_code}",
        message=message,
        details=[],
    )


async def app_error_handler(
    request: Request,
    exc: AppError,
) -> JSONResponse:
    """Serialize AppError to the unified ErrorResponse.

    Args:
        request: Incoming request whose app owns the settings snapshot.
        exc: Raised application error.

    Returns:
        JSONResponse: Serialized error.
    """
    settings = get_settings_snapshot(request.app)
    include_details = not (
        settings.app.environment == "deployment" and exc.redact_details_in_deployment
    )
    return JSONResponse(
        status_code=exc.status,
        content=jsonable_encoder(exc.response_payload(include_details=include_details)),
        headers=dict(exc.headers),
    )


async def http_error_handler(
    request: Request,  # noqa: ARG001
    exc: StarletteHTTPException,
) -> JSONResponse:
    """Serialize a FastAPI or Starlette HTTP exception into an ErrorResponse.

    Args:
        request: Incoming request (unused, kept for signature compatibility).
        exc: Raised HTTP exception carrying status and detail.

    Returns:
        JSONResponse: JSON-encoded error payload with appropriate status code.
    """
    detail_any: Any = exc.detail
    message = detail_any if isinstance(detail_any, str) else "HTTP error"

    if isinstance(detail_any, Mapping):
        context: dict[str, Any] = dict(cast("Mapping[str, Any]", detail_any))
    else:
        context = {"exception_detail": detail_any}
    status_code = getattr(exc, "status_code", status.HTTP_500_INTERNAL_SERVER_ERROR)
    _log_http_error(message=message, context=context, status_code=status_code)
    return JSONResponse(
        status_code=status_code,
        content=jsonable_encoder(
            _http_error_payload(status_code=status_code, detail_any=detail_any)
        ),
        headers=getattr(exc, "headers", None),
    )


async def validation_error_handler(
    request: Request,  # noqa: ARG001
    exc: RequestValidationError,
) -> JSONResponse:
    """Serialize validation errors (query/path/body/header) to ErrorResponse."""

    def _normalize_validation_errors(
        errs: Sequence[Mapping[str, Any]],
    ) -> list[ErrorDetail]:
        """Map Pydantic v2 validation errors into a compact, stable shape.

        Args:
            errs: Items from RequestValidationError.errors().

        Returns:
            Safe, structured validation details.
        """
        out: list[ErrorDetail] = []
        for e in errs:
            loc = cast("Sequence[Any]", e.get("loc", ()))
            location = [
                item if isinstance(item, (str, int)) else str(item) for item in loc
            ]
            out.append(
                ErrorDetail(
                    location=location,
                    message=cast("str", e.get("msg", "")),
                    type=cast("str", e.get("type", "")),
                )
            )
        return out

    violations = _normalize_validation_errors(exc.errors())
    logger.warning(
        "validation_failed",
        extra={
            "violations": [
                violation.model_dump(mode="json") for violation in violations
            ]
        },
    )

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content=jsonable_encoder(
            ErrorResponse(
                code="VALIDATION",
                message="Request validation failed.",
                details=violations,
            ),
        ),
    )


async def unexpected_error_handler(
    request: Request,  # noqa: ARG001
    exc: Exception,
) -> JSONResponse:
    """Safety-net for unexpected exceptions (do not leak internals)."""
    logger.error(
        "unexpected_error",
        exc_info=exc,
        extra={"exception_type": type(exc).__name__},
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=jsonable_encoder(
            ErrorResponse(
                code="INTERNAL_ERROR",
                message="Internal server error.",
                details=[],
            ),
        ),
    )

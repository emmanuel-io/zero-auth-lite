"""Application base error serialized by the server error handler."""

from collections.abc import Iterable, Mapping
from typing import ClassVar

from fastapi import status

from app.core.errors.responses import ErrorDetail, ErrorResponse


class AppError(RuntimeError):
    """Base exception for errors that should map cleanly to HTTP responses."""

    code: ClassVar[str] = "APP_ERROR"
    message: ClassVar[str] = "Application error."
    status: ClassVar[int] = status.HTTP_500_INTERNAL_SERVER_ERROR
    headers: ClassVar[Mapping[str, str]] = {}
    example_key: ClassVar[str | None] = None
    detail_type: ClassVar[str | None] = None
    detail_message: ClassVar[str | None] = None
    redact_details_in_deployment: ClassVar[bool] = False

    def __init__(self, *args: object) -> None:
        """Initialize and optionally format the message with positional values."""
        super().__init__(*args)
        self._formatted_message = self._format_message(args=args)

    @property
    def formatted_message(self) -> str:
        """Return the client-safe formatted error message."""
        return self._formatted_message

    @property
    def payload(self) -> ErrorResponse:
        """Return the error payload serialized by the HTTP adapter."""
        return self.response_payload()

    def response_payload(self, *, include_details: bool = True) -> ErrorResponse:
        """Return the client payload, optionally omitting diagnostic details."""
        return ErrorResponse(
            code=self.code,
            message=self.formatted_message,
            details=self._details() if include_details else [],
        )

    @classmethod
    def documented_payload(cls) -> ErrorResponse:
        """Return the static payload used to document this error."""
        return ErrorResponse(code=cls.code, message=cls.message, details=cls._details())

    @classmethod
    def documented_example_key(cls) -> str:
        """Return the internal OpenAPI example key for this error variant."""
        return cls.example_key or cls.code

    @classmethod
    def _details(cls) -> list[ErrorDetail]:
        """Build the safe structured diagnostic declared by the error class."""
        if cls.detail_type is None or cls.detail_message is None:
            return []
        return [
            ErrorDetail(
                location=[],
                message=cls.detail_message,
                type=cls.detail_type,
            )
        ]

    def _format_message(self, *, args: Iterable[object]) -> str:
        """Return a formatted message when arguments match its template."""
        if args:
            try:
                return self.message % tuple(args)
            except TypeError:
                pass
        return self.message

    def __str__(self) -> str:
        """Return a compact debug representation."""
        return f"[{self.code}] {self.formatted_message}"

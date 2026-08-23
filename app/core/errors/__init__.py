"""Application error primitives shared by domain and HTTP adapters."""

from app.core.errors.base import AppError
from app.core.errors.responses import ErrorDetail, ErrorResponse


__all__ = ["AppError", "ErrorDetail", "ErrorResponse"]

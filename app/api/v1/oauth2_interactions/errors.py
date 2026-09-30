"""Safe application errors for external OAuth2 interactions."""

from typing import ClassVar

from fastapi import status

from app.core.errors.base import AppError


class OAuth2InteractionInvalidError(AppError):
    """Hide whether an OAuth2 interaction is absent, expired, or foreign."""

    code = "OAUTH2_INTERACTION_INVALID"
    message = "The OAuth2 interaction is invalid or expired."
    status = status.HTTP_400_BAD_REQUEST
    headers: ClassVar[dict[str, str]] = {
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
    }

"""HTTP error translation for OAuth2 client administration."""

from typing import NoReturn

from fastapi import status

from app.core.errors.base import AppError
from app.oauth2.clients.management import errors as service_errors


class InvalidOAuth2ClientError(AppError):
    """Raised when an OAuth2 client configuration is invalid."""

    code = "INVALID_OAUTH2_CLIENT"
    message = "The requested OAuth2 client configuration is invalid."
    status = status.HTTP_400_BAD_REQUEST


class OAuth2ClientAdminConflictError(AppError):
    """Raised when OAuth2 client state conflicts with an administration write."""

    code = "OAUTH2_CLIENT_CONFLICT"
    message = "The OAuth2 client conflicts with existing state."
    status = status.HTTP_409_CONFLICT


class OAuth2ClientOrganizationAccessConflictError(AppError):
    """Raised when an OAuth2 client organization policy is inconsistent."""

    code = "OAUTH2_CLIENT_ORGANIZATION_ACCESS_CONFLICT"
    message = "The OAuth2 client organization policy conflicts with existing state."
    status = status.HTTP_409_CONFLICT


class OAuth2ClientNotFoundError(AppError):
    """Raised when an administered OAuth2 client does not exist."""

    code = "OAUTH2_CLIENT_NOT_FOUND"
    message = "OAuth2 client not found."
    status = status.HTTP_404_NOT_FOUND


def raise_oauth2_client_service_error(
    exc: service_errors.OAuth2ClientServiceError,
) -> NoReturn:
    """Translate a service failure into a documented application error."""
    if isinstance(exc, service_errors.InvalidOAuth2ClientPayloadError):
        raise InvalidOAuth2ClientError from exc
    if isinstance(exc, service_errors.OAuth2ClientConflictError):
        raise OAuth2ClientAdminConflictError from exc
    if isinstance(
        exc,
        service_errors.OAuth2ClientOrganizationAccessConflictError,
    ):
        raise OAuth2ClientOrganizationAccessConflictError from exc
    if isinstance(exc, service_errors.OAuth2ClientAdminNotFoundError):
        raise OAuth2ClientNotFoundError from exc
    raise AppError from exc

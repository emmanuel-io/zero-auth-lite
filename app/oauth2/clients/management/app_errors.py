"""Client-safe application errors for OAuth2 client administration."""

from dataclasses import dataclass
from typing import NoReturn

from fastapi import status

from app.core.errors.base import AppError
from app.core.errors.responses import ErrorDetail, ErrorResponse
from app.oauth2.clients.management import errors as service_errors
from app.oauth2.clients.management.errors import OAuth2ClientManagementErrorReason


@dataclass(frozen=True, slots=True)
class OAuth2ClientErrorDetail:
    """Describe one explicitly publishable client-management failure."""

    type: str
    message: str

    def to_error_detail(self) -> ErrorDetail:
        """Return the detail in the canonical application-error shape."""
        return ErrorDetail(location=[], message=self.message, type=self.type)


_SAFE_DETAIL_MESSAGES = {
    OAuth2ClientManagementErrorReason.GRANT_TYPES_REQUIRED: (
        "At least one grant type is required."
    ),
    OAuth2ClientManagementErrorReason.CLIENT_SECRET_ROTATION_REQUIRED: (
        "Use secret rotation to make this client confidential."
    ),
    OAuth2ClientManagementErrorReason.PUBLIC_CLIENT_HAS_NO_SECRET: (
        "Public clients do not have a client secret."
    ),
    OAuth2ClientManagementErrorReason.PUBLIC_AUTHORIZATION_CLIENTS_REQUIRE_CONSENT: (
        "Public authorization clients must require user consent."
    ),
    OAuth2ClientManagementErrorReason.REDIRECT_URIS_REQUIRED: (
        "Authorization-code clients require at least one redirect URI."
    ),
    OAuth2ClientManagementErrorReason.UNSUPPORTED_GRANT_TYPES: (
        "One or more requested grant types are unsupported."
    ),
    OAuth2ClientManagementErrorReason.DISABLED_GRANT_TYPES: (
        "One or more requested grant types are disabled by server policy."
    ),
    OAuth2ClientManagementErrorReason.CLIENT_CREDENTIALS_REQUIRES_CONFIDENTIAL_CLIENT: (
        "The client credentials grant requires a confidential client."
    ),
    OAuth2ClientManagementErrorReason.REFRESH_TOKEN_REQUIRES_ORIGINATING_FLOW: (
        "Refresh tokens require authorization code or device code."
    ),
    OAuth2ClientManagementErrorReason.DUPLICATE_VALUES_NOT_ALLOWED: (
        "Duplicate redirect URIs are not allowed."
    ),
    OAuth2ClientManagementErrorReason.REDIRECT_URI_FRAGMENT_NOT_ALLOWED: (
        "Redirect URIs must not contain a fragment."
    ),
    OAuth2ClientManagementErrorReason.REDIRECT_URI_HTTPS_REQUIRED: (
        "Redirect URIs require HTTPS except for HTTP loopback callbacks."
    ),
    OAuth2ClientManagementErrorReason.REDIRECT_URI_INVALID: (
        "One or more redirect URIs are invalid."
    ),
    OAuth2ClientManagementErrorReason.INVALID_ORGANIZATION_ID: (
        "One or more organization identifiers are invalid."
    ),
    OAuth2ClientManagementErrorReason.ORGANIZATION_NOT_FOUND: (
        "One or more selected organizations do not exist."
    ),
    OAuth2ClientManagementErrorReason.CLIENT_TYPE_IS_IMMUTABLE: (
        "A client's public or confidential type cannot be changed directly."
    ),
    OAuth2ClientManagementErrorReason.MACHINE_ORGANIZATION_ACCESS_INVALID: (
        "This machine organization-access mode forbids assignments."
    ),
    OAuth2ClientManagementErrorReason.MACHINE_SINGLE_ORGANIZATION_LIMIT: (
        "Single-organization machine access requires exactly one assignment."
    ),
    OAuth2ClientManagementErrorReason.MACHINE_ORGANIZATION_REQUIRED: (
        "This machine organization-access mode requires assignments."
    ),
    OAuth2ClientManagementErrorReason.MACHINE_ACCESS_REQUIRES_CLIENT_CREDENTIALS: (
        "Machine organization access requires the client credentials grant."
    ),
    OAuth2ClientManagementErrorReason.SINGLE_ORGANIZATION_REQUIRED: (
        "Single-organization user access requires exactly one assignment."
    ),
    OAuth2ClientManagementErrorReason.SELECTED_ORGANIZATION_REQUIRED: (
        "Selected-organization user access requires at least one assignment."
    ),
    OAuth2ClientManagementErrorReason.UNRESTRICTED_ORGANIZATIONS_FORBIDDEN: (
        "Unrestricted user access does not accept organization assignments."
    ),
}
_SAFE_DETAILS = {
    reason: OAuth2ClientErrorDetail(type=reason.value, message=message)
    for reason, message in _SAFE_DETAIL_MESSAGES.items()
}

_INVALID_CONFIGURATION_DETAIL = OAuth2ClientErrorDetail(
    type="oauth2_client_configuration_invalid",
    message="The requested OAuth2 client configuration is invalid.",
)
_ORGANIZATION_CONFLICT_DETAIL = OAuth2ClientErrorDetail(
    type="oauth2_client_organization_access_conflict",
    message="The OAuth2 client organization policy conflicts with existing state.",
)


def _safe_detail(
    reason: OAuth2ClientManagementErrorReason | None,
    *,
    fallback: OAuth2ClientErrorDetail,
) -> ErrorDetail:
    """Return a typed public detail or the private-diagnostic fallback."""
    if reason is None:
        return fallback.to_error_detail()
    return _SAFE_DETAILS.get(reason, fallback).to_error_detail()


class OAuth2ClientManagementAppError(AppError):
    """Base application error with an optional runtime-safe explanation."""

    def __init__(self, detail: ErrorDetail | None = None) -> None:
        """Initialize the error with a safe transport-neutral detail."""
        super().__init__()
        self.detail = detail

    @property
    def display_message(self) -> str:
        """Return the most useful safe message for an HTML response."""
        return self.detail.message if self.detail is not None else self.message

    def response_payload(self, *, include_details: bool = True) -> ErrorResponse:
        """Include the runtime detail in the canonical JSON envelope."""
        payload = super().response_payload(include_details=include_details)
        if include_details and self.detail is not None:
            payload.details = [self.detail]
        return payload


class InvalidOAuth2ClientError(OAuth2ClientManagementAppError):
    """Raised when an OAuth2 client configuration is invalid."""

    code = "INVALID_OAUTH2_CLIENT"
    message = "The requested OAuth2 client configuration is invalid."
    status = status.HTTP_400_BAD_REQUEST
    detail_type = _INVALID_CONFIGURATION_DETAIL.type
    detail_message = _INVALID_CONFIGURATION_DETAIL.message


class OAuth2ClientManagementConflictError(OAuth2ClientManagementAppError):
    """Raised when OAuth2 client state conflicts with an administration write."""

    code = "OAUTH2_CLIENT_CONFLICT"
    message = "The OAuth2 client conflicts with existing state."
    status = status.HTTP_409_CONFLICT


class OAuth2ClientOrganizationAccessConflictError(OAuth2ClientManagementAppError):
    """Raised when an OAuth2 client organization policy is inconsistent."""

    code = "OAUTH2_CLIENT_ORGANIZATION_ACCESS_CONFLICT"
    message = "The OAuth2 client organization policy conflicts with existing state."
    status = status.HTTP_409_CONFLICT
    detail_type = _ORGANIZATION_CONFLICT_DETAIL.type
    detail_message = _ORGANIZATION_CONFLICT_DETAIL.message


class OAuth2ClientNotFoundError(OAuth2ClientManagementAppError):
    """Raised when an administered OAuth2 client does not exist."""

    code = "OAUTH2_CLIENT_NOT_FOUND"
    message = "OAuth2 client not found."
    status = status.HTTP_404_NOT_FOUND


def raise_oauth2_client_management_error(
    exc: service_errors.OAuth2ClientServiceError,
) -> NoReturn:
    """Translate a known service failure into a shared application error."""
    if isinstance(exc, service_errors.InvalidOAuth2ClientPayloadError):
        detail = _safe_detail(exc.reason, fallback=_INVALID_CONFIGURATION_DETAIL)
        raise InvalidOAuth2ClientError(detail) from exc
    if isinstance(exc, service_errors.OAuth2ClientConflictError):
        raise OAuth2ClientManagementConflictError from exc
    if isinstance(
        exc,
        service_errors.OAuth2ClientOrganizationAccessConflictError,
    ):
        detail = _safe_detail(exc.reason, fallback=_ORGANIZATION_CONFLICT_DETAIL)
        raise OAuth2ClientOrganizationAccessConflictError(detail) from exc
    if isinstance(exc, service_errors.OAuth2ClientManagementNotFoundError):
        raise OAuth2ClientNotFoundError from exc
    msg = f"Unhandled OAuth2 client service error: {type(exc).__name__}"
    raise RuntimeError(msg) from exc

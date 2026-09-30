"""Errors raised by OAuth2 client-management services."""

from enum import StrEnum


class OAuth2ClientManagementErrorReason(StrEnum):
    """Stable reasons that may be published by client-management transports."""

    GRANT_TYPES_REQUIRED = "grant_types_required"
    # These values name validation failures; they are not credentials.
    CLIENT_SECRET_ROTATION_REQUIRED = "client_secret_rotation_required"  # noqa: S105
    PUBLIC_CLIENT_HAS_NO_SECRET = "public_client_has_no_secret"  # noqa: S105
    PUBLIC_AUTHORIZATION_CLIENTS_REQUIRE_CONSENT = (
        "public_authorization_clients_require_consent"
    )
    REDIRECT_URIS_REQUIRED = "redirect_uris_required"
    UNSUPPORTED_GRANT_TYPES = "unsupported_grant_types"
    DISABLED_GRANT_TYPES = "disabled_grant_types"
    CLIENT_CREDENTIALS_REQUIRES_CONFIDENTIAL_CLIENT = (
        "client_credentials_requires_confidential_client"
    )
    REFRESH_TOKEN_REQUIRES_ORIGINATING_FLOW = "refresh_token_requires_originating_flow"  # noqa: S105
    DUPLICATE_VALUES_NOT_ALLOWED = "duplicate_values_not_allowed"
    REDIRECT_URI_FRAGMENT_NOT_ALLOWED = "redirect_uri_fragment_not_allowed"
    REDIRECT_URI_HTTPS_REQUIRED = "redirect_uri_https_required"
    REDIRECT_URI_INVALID = "redirect_uri_invalid"
    INVALID_ORGANIZATION_ID = "invalid_organization_id"
    ORGANIZATION_NOT_FOUND = "organization_not_found"
    CLIENT_TYPE_IS_IMMUTABLE = "client_type_is_immutable"
    MACHINE_ORGANIZATION_ACCESS_INVALID = (
        "oauth2_client_machine_organization_access_invalid"
    )
    MACHINE_SINGLE_ORGANIZATION_LIMIT = (
        "oauth2_client_machine_single_organization_limit"
    )
    MACHINE_ORGANIZATION_REQUIRED = "oauth2_client_machine_organization_required"
    MACHINE_ACCESS_REQUIRES_CLIENT_CREDENTIALS = (
        "oauth2_client_machine_access_requires_client_credentials"
    )
    SINGLE_ORGANIZATION_REQUIRED = "oauth2_client_single_organization_required"
    SELECTED_ORGANIZATION_REQUIRED = "oauth2_client_selected_organization_required"
    UNRESTRICTED_ORGANIZATIONS_FORBIDDEN = (
        "oauth2_client_unrestricted_organizations_forbidden"
    )


class OAuth2ClientServiceError(Exception):
    """Base exception for OAuth2 client administration failures."""


class InvalidOAuth2ClientPayloadError(OAuth2ClientServiceError):
    """Raised when OAuth2 client settings are invalid."""

    def __init__(
        self,
        reason: OAuth2ClientManagementErrorReason | None = None,
        *,
        context: tuple[str, ...] = (),
        diagnostic: str | None = None,
    ) -> None:
        """Initialize a publishable reason or a private diagnostic."""
        if (reason is None) == (diagnostic is None):
            msg = "Provide exactly one OAuth2 client reason or diagnostic."
            raise ValueError(msg)
        super().__init__(reason.value if reason is not None else diagnostic)
        self.reason = reason
        self.context = context
        self.diagnostic = diagnostic


class OAuth2ClientConflictError(OAuth2ClientServiceError):
    """Raised when an OAuth2 client cannot be created due to a conflict."""


class OAuth2ClientOrganizationAccessConflictError(OAuth2ClientServiceError):
    """Raised when an organization policy transition violates its cardinality."""

    def __init__(
        self,
        reason: OAuth2ClientManagementErrorReason | None = None,
        *,
        context: tuple[str, ...] = (),
        diagnostic: str | None = None,
    ) -> None:
        """Initialize a publishable reason or a private diagnostic."""
        if (reason is None) == (diagnostic is None):
            msg = "Provide exactly one OAuth2 client reason or diagnostic."
            raise ValueError(msg)
        super().__init__(reason.value if reason is not None else diagnostic)
        self.reason = reason
        self.context = context
        self.diagnostic = diagnostic


class OAuth2ClientManagementNotFoundError(OAuth2ClientServiceError):
    """Raised when a globally administered OAuth2 client cannot be found."""

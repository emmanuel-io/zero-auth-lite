"""Errors raised by OAuth2 client-management services."""


class OAuth2ClientServiceError(Exception):
    """Base exception for OAuth2 client administration failures."""


class InvalidOAuth2ClientPayloadError(OAuth2ClientServiceError):
    """Raised when OAuth2 client settings are invalid."""

    def __init__(self, detail: str) -> None:
        """Initialize the invalid payload error."""
        super().__init__(detail)
        self.detail = detail


class OAuth2ClientConflictError(OAuth2ClientServiceError):
    """Raised when an OAuth2 client cannot be created due to a conflict."""


class OAuth2ClientOrganizationAccessConflictError(OAuth2ClientServiceError):
    """Raised when an organization policy transition violates its cardinality."""

    def __init__(self, detail: str) -> None:
        """Initialize a stable administration conflict."""
        super().__init__(detail)
        self.detail = detail


class OAuth2ClientAdminNotFoundError(OAuth2ClientServiceError):
    """Raised when a globally administered OAuth2 client cannot be found."""

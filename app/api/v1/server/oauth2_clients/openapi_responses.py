"""OpenAPI responses for OAuth2 client administration routes."""

from app.api.error_responses import app_error_responses
from app.api.schemas import OpenAPIResponses
from app.browser_sessions.errors import (
    BrowserSessionInvalidError,
    CSRF_ERRORS,
)
from app.core.errors.common import ForbiddenOperationError, UnauthorizedError
from app.oauth2.clients.management.app_errors import (
    InvalidOAuth2ClientError,
    OAuth2ClientManagementConflictError,
    OAuth2ClientNotFoundError,
    OAuth2ClientOrganizationAccessConflictError,
)


AUTH_ERROR_RESPONSES = app_error_responses(
    UnauthorizedError,
    BrowserSessionInvalidError,
    ForbiddenOperationError,
    descriptions={
        401: "Authentication is missing or invalid.",
        403: (
            "Server-operator authority or the required OAuth2 client scope is missing."
        ),
    },
)
WRITE_AUTH_ERROR_RESPONSES = app_error_responses(
    UnauthorizedError,
    BrowserSessionInvalidError,
    ForbiddenOperationError,
    *CSRF_ERRORS,
    descriptions={
        401: "Authentication is missing or invalid.",
        403: (
            "Server-operator authority or the required OAuth2 client scope is "
            "missing, or a browser-session request lacks valid CSRF proof."
        ),
    },
)
INVALID_CLIENT_RESPONSE = app_error_responses(
    InvalidOAuth2ClientError,
    descriptions={400: "The requested OAuth2 client configuration is invalid."},
)
CLIENT_NOT_FOUND_RESPONSE = app_error_responses(
    OAuth2ClientNotFoundError,
    descriptions={404: "OAuth2 client not found."},
)
CLIENT_CONFLICT_RESPONSE = app_error_responses(
    OAuth2ClientManagementConflictError,
    OAuth2ClientOrganizationAccessConflictError,
    descriptions={
        409: "The OAuth2 client or organization policy conflicts with existing state."
    },
)
SECRET_RESPONSE_HEADERS: dict[str, dict[str, object]] = {
    "Cache-Control": {
        "description": (
            "Prevents storage of a response containing a newly issued secret."
        ),
        "schema": {"type": "string", "const": "no-store"},
    },
    "Pragma": {
        "description": (
            "Legacy cache prevention for a response containing a newly issued secret."
        ),
        "schema": {"type": "string", "const": "no-cache"},
    },
}
CREATE_CLIENT_RESPONSES: OpenAPIResponses = (
    {
        201: {
            "description": (
                "OAuth2 client created; "
                "cache-prevention headers accompany a returned secret."
            ),
            "headers": SECRET_RESPONSE_HEADERS,
        }
    }
    | WRITE_AUTH_ERROR_RESPONSES
    | INVALID_CLIENT_RESPONSE
    | CLIENT_CONFLICT_RESPONSE
)
ROTATE_SECRET_RESPONSES: OpenAPIResponses = (
    {
        200: {
            "description": "Replacement client secret returned once.",
            "headers": SECRET_RESPONSE_HEADERS,
        }
    }
    | WRITE_AUTH_ERROR_RESPONSES
    | INVALID_CLIENT_RESPONSE
    | CLIENT_NOT_FOUND_RESPONSE
)

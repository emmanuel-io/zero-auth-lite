"""Shared transport contract for OAuth2 client administration routes."""

from typing import Annotated

from fastapi import Path, Security

from app.api.error_responses import app_error_responses
from app.api.schemas import OpenAPIResponses
from app.api.v1.admin.oauth2_clients.errors import (
    InvalidOAuth2ClientError,
    OAuth2ClientAdminConflictError,
    OAuth2ClientNotFoundError,
    OAuth2ClientOrganizationAccessConflictError,
)
from app.browser_sessions.errors import (
    CSRFCookieHeaderMismatchError,
    CSRFHeaderSessionMismatchError,
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
    SessionInvalidError,
)
from app.errors import ForbiddenOperationError, UnauthorizedError
from app.oauth2.specs import OAuth2Specs
from app.security.authorization import require_operator_permission
from app.security.dtos import UserPrincipalContext
from app.security.permissions import Permission


OAUTH2_CLIENTS_PREFIX = "/oauth2/clients"
OAuth2ClientIdPath = Annotated[
    str,
    Path(
        min_length=1,
        max_length=OAuth2Specs.CLIENT_ID_LENGTH_MAX,
        description="Global OAuth2 client identifier.",
    ),
]
AUTH_ERROR_RESPONSES = app_error_responses(
    UnauthorizedError,
    SessionInvalidError,
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
    SessionInvalidError,
    ForbiddenOperationError,
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
    CSRFCookieHeaderMismatchError,
    CSRFHeaderSessionMismatchError,
    descriptions={
        401: "Authentication is missing or invalid.",
        403: (
            "Server-operator authority, the required OAuth2 client scope, and valid "
            "CSRF proof are required."
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
    OAuth2ClientAdminConflictError,
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
OperatorOAuth2ClientsReadDep = Annotated[
    UserPrincipalContext,
    Security(
        require_operator_permission(Permission.OAUTH2_CLIENTS_READ),
        scopes=[Permission.OAUTH2_CLIENTS_READ.value],
    ),
]
OperatorOAuth2ClientsWriteDep = Annotated[
    UserPrincipalContext,
    Security(
        require_operator_permission(Permission.OAUTH2_CLIENTS_WRITE),
        scopes=[Permission.OAUTH2_CLIENTS_WRITE.value],
    ),
]

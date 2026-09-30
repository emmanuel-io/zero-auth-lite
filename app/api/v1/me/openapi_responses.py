"""Shared OpenAPI error responses for current-user routes."""

from app.api.error_responses import app_error_responses
from app.browser_sessions.errors import (
    BrowserSessionInvalidError,
    CSRF_ERRORS,
)
from app.core.errors.common import (
    ForbiddenOperationError,
    ObjectAlreadyExistsError,
    UnauthorizedError,
)
from app.identity.errors import CurrentPasswordMismatchError
from app.identity.users.errors import (
    LastActiveOperatorError,
    LastActiveOrganizationAdminError,
)


PROFILE_AUTH_ERROR_RESPONSES = app_error_responses(
    UnauthorizedError,
    BrowserSessionInvalidError,
    ForbiddenOperationError,
    descriptions={
        401: "Authentication is missing or invalid.",
        403: "The required profile scope is missing.",
    },
)
PROFILE_WRITE_AUTH_ERROR_RESPONSES = app_error_responses(
    UnauthorizedError,
    BrowserSessionInvalidError,
    ForbiddenOperationError,
    *CSRF_ERRORS,
    descriptions={
        401: "Authentication is missing or invalid.",
        403: (
            "The required profile scope is missing, or a browser-session request "
            "lacks valid CSRF proof."
        ),
    },
)
PROFILE_WRITE_ERROR_RESPONSES = (
    PROFILE_WRITE_AUTH_ERROR_RESPONSES
    | app_error_responses(
        ObjectAlreadyExistsError,
        descriptions={409: "The requested email address is already in use."},
    )
)
BROWSER_SESSION_AUTH_ERROR_RESPONSES = app_error_responses(
    BrowserSessionInvalidError,
    descriptions={401: "A valid browser session is required."},
)
BROWSER_SESSION_WRITE_AUTH_ERROR_RESPONSES = app_error_responses(
    BrowserSessionInvalidError,
    *CSRF_ERRORS,
    descriptions={
        401: "A valid browser session is required.",
        403: "Valid CSRF proof is required.",
    },
)
ACCOUNT_DELETE_ERROR_RESPONSES = app_error_responses(
    BrowserSessionInvalidError,
    ForbiddenOperationError,
    LastActiveOperatorError,
    LastActiveOrganizationAdminError,
    *CSRF_ERRORS,
    descriptions={
        401: "A valid browser session is required.",
        403: "Account deletion is forbidden or valid CSRF proof is missing.",
        409: (
            "The final active server operator or organization administrator "
            "cannot be deleted."
        ),
    },
)
PASSWORD_CHANGE_ERROR_RESPONSES = app_error_responses(
    BrowserSessionInvalidError,
    CurrentPasswordMismatchError,
    *CSRF_ERRORS,
    descriptions={
        401: "A valid browser session and current password are required.",
        403: "Valid CSRF proof is required.",
    },
)

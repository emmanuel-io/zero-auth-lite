"""Shared OpenAPI error responses for current-user routes."""

from app.api.error_responses import app_error_responses
from app.browser_sessions.errors import (
    CSRFCookieHeaderMismatchError,
    CSRFHeaderSessionMismatchError,
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
    SessionInvalidError,
)
from app.errors import (
    ForbiddenOperationError,
    ObjectAlreadyExistsError,
    UnauthorizedError,
)
from app.identity.errors import CurrentPasswordMismatchError
from app.identity.users.errors import LastActiveOperatorError


PROFILE_AUTH_ERROR_RESPONSES = app_error_responses(
    UnauthorizedError,
    SessionInvalidError,
    ForbiddenOperationError,
    descriptions={
        401: "Authentication is missing or invalid.",
        403: "The required profile scope is missing.",
    },
)
PROFILE_WRITE_AUTH_ERROR_RESPONSES = app_error_responses(
    UnauthorizedError,
    SessionInvalidError,
    ForbiddenOperationError,
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
    CSRFCookieHeaderMismatchError,
    CSRFHeaderSessionMismatchError,
    descriptions={
        401: "Authentication is missing or invalid.",
        403: "The required profile scope and valid CSRF proof are required.",
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
    SessionInvalidError,
    descriptions={401: "A valid browser session is required."},
)
BROWSER_SESSION_WRITE_AUTH_ERROR_RESPONSES = app_error_responses(
    SessionInvalidError,
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
    CSRFCookieHeaderMismatchError,
    CSRFHeaderSessionMismatchError,
    descriptions={
        401: "A valid browser session is required.",
        403: "Valid CSRF proof is required.",
    },
)
ACCOUNT_DELETE_ERROR_RESPONSES = app_error_responses(
    SessionInvalidError,
    ForbiddenOperationError,
    LastActiveOperatorError,
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
    CSRFCookieHeaderMismatchError,
    CSRFHeaderSessionMismatchError,
    descriptions={
        401: "A valid browser session is required.",
        403: "Account deletion is forbidden or valid CSRF proof is missing.",
        409: "The final active server operator cannot be deleted.",
    },
)
PASSWORD_CHANGE_ERROR_RESPONSES = app_error_responses(
    SessionInvalidError,
    CurrentPasswordMismatchError,
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
    CSRFCookieHeaderMismatchError,
    CSRFHeaderSessionMismatchError,
    descriptions={
        401: "A valid browser session and current password are required.",
        403: "Valid CSRF proof is required.",
    },
)

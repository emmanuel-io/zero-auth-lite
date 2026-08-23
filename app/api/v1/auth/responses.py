"""Shared OpenAPI error responses for authentication workflows."""

from app.api.error_responses import app_error_responses
from app.auth_tokens.errors import InvalidAuthTokenError
from app.errors import ObjectAlreadyExistsError


REGISTRATION_ERROR_RESPONSES = app_error_responses(
    ObjectAlreadyExistsError,
    descriptions={409: "The email address is already registered."},
)
AUTH_TOKEN_CONFIRMATION_ERROR_RESPONSES = app_error_responses(
    InvalidAuthTokenError,
    descriptions={400: "The authentication token is invalid or expired."},
)

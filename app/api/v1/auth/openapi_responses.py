"""Shared OpenAPI error responses for authentication workflows."""

from app.api.error_responses import app_error_responses
from app.core.errors.common import ObjectAlreadyExistsError
from app.db.errors import (
    CheckViolationError,
    ForeignKeyViolationError,
    NotNullViolationError,
    UniqueViolationError,
)
from app.workflow_tokens.errors import InvalidWorkflowTokenError


REGISTRATION_ERROR_RESPONSES = app_error_responses(
    ObjectAlreadyExistsError,
    UniqueViolationError,
    CheckViolationError,
    ForeignKeyViolationError,
    NotNullViolationError,
    descriptions={
        409: "The email address is already registered or stored data conflicts."
    },
)
WORKFLOW_TOKEN_CONFIRMATION_ERROR_RESPONSES = app_error_responses(
    InvalidWorkflowTokenError,
    descriptions={400: "The workflow token is invalid or expired."},
)

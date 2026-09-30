"""Shared OpenAPI error groups for user-administration routes."""

from app.api.error_responses import app_error_responses
from app.api.schemas import OpenAPIResponses
from app.browser_sessions.errors import (
    BrowserSessionInvalidError,
    CSRF_ERRORS,
)
from app.core.errors.base import AppError
from app.core.errors.common import (
    ForbiddenOperationError,
    ObjectAlreadyExistsError,
    UnauthorizedError,
)
from app.db.errors import (
    CheckViolationError,
    ForeignKeyViolationError,
    NotNullViolationError,
    UniqueViolationError,
)


USER_DATA_CONFLICT_ERRORS = (
    ObjectAlreadyExistsError,
    UniqueViolationError,
    CheckViolationError,
    ForeignKeyViolationError,
    NotNullViolationError,
)


def user_auth_error_responses(
    *,
    authentication_description: str,
    forbidden_description: str,
    require_csrf: bool = False,
) -> OpenAPIResponses:
    """Build authentication responses with surface-owned explanations."""
    csrf_errors: tuple[type[AppError], ...] = ()
    if require_csrf:
        csrf_errors = CSRF_ERRORS
    return app_error_responses(
        UnauthorizedError,
        BrowserSessionInvalidError,
        ForbiddenOperationError,
        *csrf_errors,
        descriptions={
            401: authentication_description,
            403: forbidden_description,
        },
    )


def user_data_conflict_responses(
    *domain_errors: type[AppError], description: str
) -> OpenAPIResponses:
    """Build persistence and domain conflict responses for user mutations."""
    return app_error_responses(
        *USER_DATA_CONFLICT_ERRORS,
        *domain_errors,
        descriptions={409: description},
    )

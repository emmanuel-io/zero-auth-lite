"""OpenAPI responses for operator user administration."""

from app.api.error_responses import app_error_responses
from app.api.errors import StartDateAfterEndDateError
from app.api.v1.user_contract import (
    user_auth_error_responses,
    user_data_conflict_responses,
)
from app.core.errors.common import ObjectNotFoundError
from app.identity.users.errors import (
    InactiveUserInvitationError,
    LastActiveOperatorError,
    LastActiveOrganizationAdminError,
)


AUTH_ERROR_RESPONSES = user_auth_error_responses(
    authentication_description="Authentication is missing or invalid.",
    forbidden_description=(
        "Server-operator authority or the required scope is missing."
    ),
)
WRITE_AUTH_ERROR_RESPONSES = user_auth_error_responses(
    authentication_description="Authentication is missing or invalid.",
    forbidden_description=(
        "Server-operator authority or the required scope is missing, or a "
        "browser-session request lacks valid CSRF proof."
    ),
    require_csrf=True,
)
USER_NOT_FOUND_RESPONSE = app_error_responses(
    ObjectNotFoundError,
    descriptions={404: "User or target organization not found."},
)
USER_LIST_ERROR_RESPONSES = AUTH_ERROR_RESPONSES | app_error_responses(
    StartDateAfterEndDateError,
    descriptions={400: "The created date range is invalid."},
)
USER_CREATE_CONFLICT_RESPONSES = user_data_conflict_responses(
    description="User data conflicts with existing data.",
)
USER_INVITATION_CONFLICT_RESPONSES = app_error_responses(
    InactiveUserInvitationError,
    descriptions={409: "The user cannot receive another invitation."},
)
USER_UPDATE_CONFLICT_RESPONSES = user_data_conflict_responses(
    LastActiveOperatorError,
    LastActiveOrganizationAdminError,
    description=(
        "User data conflicts with existing data or a required operator or "
        "organization-administrator lifecycle invariant."
    ),
)
USER_DELETE_CONFLICT_RESPONSES = app_error_responses(
    LastActiveOperatorError,
    LastActiveOrganizationAdminError,
    descriptions={
        409: (
            "The final active server operator or organization administrator "
            "cannot be deleted."
        )
    },
)

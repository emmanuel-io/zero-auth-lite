"""OpenAPI responses for organization user administration."""

from app.api.error_responses import app_error_responses
from app.api.errors import StartDateAfterEndDateError
from app.api.v1.user_contract import (
    user_auth_error_responses,
    user_data_conflict_responses,
)
from app.core.errors.common import ObjectNotFoundError
from app.identity.users.errors import (
    InactiveUserInvitationError,
    LastActiveOrganizationAdminError,
)


ORGANIZATION_USER_READ_AUTH_RESPONSES = user_auth_error_responses(
    authentication_description="Missing or invalid authentication.",
    forbidden_description=(
        "Organization-admin role and the required permission are both required. "
        "An OAuth2 scope or server-operator role alone does not grant "
        "organization-admin access."
    ),
)
ORGANIZATION_USER_WRITE_AUTH_RESPONSES = user_auth_error_responses(
    authentication_description="Missing or invalid authentication.",
    forbidden_description=(
        "Organization-admin role and the required permission are both required. "
        "An OAuth2 scope or server-operator role alone does not grant "
        "organization-admin access. Browser sessions must pass CSRF validation, "
        "and operator accounts cannot be mutated through this organization surface."
    ),
    require_csrf=True,
)
ORGANIZATION_USER_NOT_FOUND_RESPONSE = app_error_responses(
    ObjectNotFoundError,
    descriptions={404: "User not found in the authenticated organization."},
)
ORGANIZATION_USER_CREATE_CONFLICT_RESPONSES = user_data_conflict_responses(
    description="The requested data conflicts with existing user state.",
)
ORGANIZATION_USER_INVITATION_CONFLICT_RESPONSES = app_error_responses(
    InactiveUserInvitationError,
    descriptions={409: "The user cannot receive another invitation."},
)
ORGANIZATION_USER_UPDATE_CONFLICT_RESPONSES = user_data_conflict_responses(
    LastActiveOrganizationAdminError,
    description=(
        "The requested data conflicts with existing user state or would remove "
        "the final active organization administrator."
    ),
)
ORGANIZATION_USER_DELETE_CONFLICT_RESPONSES = app_error_responses(
    LastActiveOrganizationAdminError,
    descriptions={
        409: "The final active organization administrator cannot be deleted."
    },
)
ORGANIZATION_USER_LIST_RESPONSES = (
    ORGANIZATION_USER_READ_AUTH_RESPONSES
    | app_error_responses(
        StartDateAfterEndDateError,
        descriptions={400: "The created date range is invalid."},
    )
)

"""Cardinality rules for user-backed OAuth2 organization access."""

from uuid import UUID

from app.oauth2.clients.access import (
    OAuth2ClientUserOrganizationAccess,
    organization_assignment_count_is_valid,
)
from app.oauth2.clients.management.errors import (
    OAuth2ClientManagementErrorReason,
    OAuth2ClientOrganizationAccessConflictError,
)


def validate_user_organization_policy(
    *,
    mode: OAuth2ClientUserOrganizationAccess,
    organization_ids: list[UUID],
) -> None:
    """Require assignment cardinality consistent with the selected mode."""
    assignment_count = len(organization_ids)
    if mode == OAuth2ClientUserOrganizationAccess.UNRESTRICTED:
        if not organization_assignment_count_is_valid(
            mode=mode, assignment_count=assignment_count
        ):
            raise OAuth2ClientOrganizationAccessConflictError(
                OAuth2ClientManagementErrorReason.UNRESTRICTED_ORGANIZATIONS_FORBIDDEN
            )
        return
    if mode == OAuth2ClientUserOrganizationAccess.SINGLE:
        if not organization_assignment_count_is_valid(
            mode=mode, assignment_count=assignment_count
        ):
            raise OAuth2ClientOrganizationAccessConflictError(
                OAuth2ClientManagementErrorReason.SINGLE_ORGANIZATION_REQUIRED
            )
        return
    if not organization_assignment_count_is_valid(
        mode=mode, assignment_count=assignment_count
    ):
        raise OAuth2ClientOrganizationAccessConflictError(
            OAuth2ClientManagementErrorReason.SELECTED_ORGANIZATION_REQUIRED
        )


def user_organization_policy_narrowed(
    *,
    previous_mode: OAuth2ClientUserOrganizationAccess,
    current_mode: OAuth2ClientUserOrganizationAccess,
    previous_organization_ids: set[int],
    current_organization_ids: set[int],
) -> bool:
    """Return whether a user-organization policy removes client authority."""
    if previous_mode == OAuth2ClientUserOrganizationAccess.UNRESTRICTED:
        return current_mode != OAuth2ClientUserOrganizationAccess.UNRESTRICTED
    if current_mode == OAuth2ClientUserOrganizationAccess.UNRESTRICTED:
        return False
    return bool(previous_organization_ids - current_organization_ids)

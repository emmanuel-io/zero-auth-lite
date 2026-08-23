"""Current-organization metadata administration API routes."""

from typing import Annotated

from fastapi import APIRouter, Security, status

from app.api.error_responses import app_error_responses
from app.api.v1.organization.schemas import (
    CurrentOrganizationPatchRequest,
    CurrentOrganizationResponse,
)
from app.browser_sessions.errors import (
    CSRFCookieHeaderMismatchError,
    CSRFHeaderSessionMismatchError,
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
    SessionInvalidError,
)
from app.db.errors import CheckViolationError
from app.errors import ForbiddenOperationError, ObjectNotFoundError, UnauthorizedError
from app.identity.dependencies import OrganizationMetadataServiceDep
from app.identity.organizations.dtos import OrganizationReadDTO, OrganizationUpdateDTO
from app.openapi_tags import ORGANIZATION_ADMINISTRATION_V1_TAG
from app.security.authorization import require_organization_admin_permission
from app.security.dtos import UserPrincipalContext
from app.security.permissions import Permission


def current_organization_response(
    dto: OrganizationReadDTO,
) -> CurrentOrganizationResponse:
    """Convert current-organization service data to an HTTP response."""
    return CurrentOrganizationResponse(name=dto.name, public_id=dto.public_id)


router = APIRouter(tags=[ORGANIZATION_ADMINISTRATION_V1_TAG])


@router.get(
    "",
    status_code=status.HTTP_200_OK,
    summary="Get current organization metadata",
    responses=app_error_responses(
        UnauthorizedError,
        SessionInvalidError,
        ForbiddenOperationError,
        ObjectNotFoundError,
        descriptions={
            401: "Missing or invalid authentication.",
            403: (
                "Organization-admin role and the organization:read permission are both "
                "required. Possessing the OAuth2 scope alone does not grant "
                "organization-admin access."
            ),
            404: "Organization not found.",
        },
    )
    | {200: {"description": "Organization retrieved successfully."}},
)
async def get_current_organization(
    _principal: Annotated[
        UserPrincipalContext,
        Security(
            require_organization_admin_permission(Permission.ORGANIZATION_READ),
            scopes=[Permission.ORGANIZATION_READ.value],
        ),
    ],
    organization_service: OrganizationMetadataServiceDep,
) -> CurrentOrganizationResponse:
    """Retrieve metadata for the authenticated user's organization."""
    dto = await organization_service.get()
    return current_organization_response(dto)


@router.patch(
    "",
    status_code=status.HTTP_200_OK,
    summary="Patch current organization metadata",
    responses=app_error_responses(
        UnauthorizedError,
        SessionInvalidError,
        ForbiddenOperationError,
        CSRFMissingCookieError,
        CSRFMissingHeaderError,
        CSRFCookieHeaderMismatchError,
        CSRFHeaderSessionMismatchError,
        ObjectNotFoundError,
        CheckViolationError,
        descriptions={
            401: "Missing or invalid authentication.",
            403: (
                "Organization-admin role and the organization:write permission are "
                "both required. An OAuth2 scope or server-operator role alone does "
                "not grant organization-admin access; browser sessions must also "
                "pass CSRF validation."
            ),
            404: "Organization not found.",
            409: "Organization patch conflicts with existing data.",
        },
    )
    | {200: {"description": "Organization patched successfully."}},
)
async def patch_current_organization(
    _admin_ctx: Annotated[
        UserPrincipalContext,
        Security(
            require_organization_admin_permission(Permission.ORGANIZATION_WRITE),
            scopes=[Permission.ORGANIZATION_WRITE.value],
        ),
    ],
    payload: CurrentOrganizationPatchRequest,
    organization_service: OrganizationMetadataServiceDep,
) -> CurrentOrganizationResponse:
    """Patch metadata for the authenticated administrator's organization."""
    dto = OrganizationUpdateDTO(name=payload.name)
    result = await organization_service.update(dto=dto)
    return current_organization_response(result)

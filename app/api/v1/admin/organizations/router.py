"""Server-operator organization administration API routes."""

from typing import Annotated

from fastapi import APIRouter, Query, Security, status

from app.api.dependencies.ids import OrganizationIdPath, parse_organization_id
from app.api.error_responses import app_error_responses
from app.api.schemas import (
    DEFAULT_PAGE_LIMIT_MAX,
    PaginatedResponse,
)
from app.api.v1.admin.organizations.schemas import (
    OperatorOrganizationCreateRequest,
    OperatorOrganizationPatchRequest,
    OperatorOrganizationResponse,
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
from app.identity.dependencies import OperatorOrganizationsServiceDep
from app.identity.organizations.dtos import OrganizationCreateDTO, OrganizationUpdateDTO
from app.security.authorization import require_operator_permission
from app.security.dtos import UserPrincipalContext
from app.security.permissions import Permission


router = APIRouter(prefix="/organizations")
OrganizationListResponse = PaginatedResponse[OperatorOrganizationResponse]
AUTH_ERROR_RESPONSES = app_error_responses(
    UnauthorizedError,
    SessionInvalidError,
    ForbiddenOperationError,
    descriptions={
        401: "Authentication is missing or invalid.",
        403: "Server-operator authority or the required scope is missing.",
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
            "Server-operator authority, the required scope, and valid CSRF proof "
            "are required."
        ),
    },
)
ORGANIZATION_NOT_FOUND_RESPONSE = app_error_responses(
    ObjectNotFoundError,
    descriptions={404: "Organization not found."},
)
ORGANIZATION_CONFLICT_RESPONSE = app_error_responses(
    CheckViolationError,
    descriptions={409: "Organization data violates a stored-data rule."},
)
OperatorOrganizationsReadDep = Annotated[
    UserPrincipalContext,
    Security(
        require_operator_permission(Permission.ORGANIZATIONS_READ),
        scopes=[Permission.ORGANIZATIONS_READ.value],
    ),
]
OperatorOrganizationsWriteDep = Annotated[
    UserPrincipalContext,
    Security(
        require_operator_permission(Permission.ORGANIZATIONS_WRITE),
        scopes=[Permission.ORGANIZATIONS_WRITE.value],
    ),
]


@router.get(
    "",
    status_code=status.HTTP_200_OK,
    summary="List organizations across the server",
    responses=AUTH_ERROR_RESPONSES,
)
async def list_organizations(
    organizations_service: OperatorOrganizationsServiceDep,
    _operator_ctx: OperatorOrganizationsReadDep,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=DEFAULT_PAGE_LIMIT_MAX)] = 20,
) -> OrganizationListResponse:
    """List organizations through the server-operator control plane."""
    results = await organizations_service.list(offset=offset, limit=limit)
    total = await organizations_service.count()
    return OrganizationListResponse(
        items=[
            OperatorOrganizationResponse(name=result.name, public_id=result.public_id)
            for result in results
        ],
        offset=offset,
        limit=limit,
        total=total,
    )


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    summary="Create an organization across the server",
    responses=WRITE_AUTH_ERROR_RESPONSES | ORGANIZATION_CONFLICT_RESPONSE,
)
async def create_organization(
    payload: OperatorOrganizationCreateRequest,
    organizations_service: OperatorOrganizationsServiceDep,
    _operator_ctx: OperatorOrganizationsWriteDep,
) -> OperatorOrganizationResponse:
    """Create an organization through the server-operator control plane."""
    dto = OrganizationCreateDTO(name=payload.name)
    result = await organizations_service.create(dto=dto)
    return OperatorOrganizationResponse(name=result.name, public_id=result.public_id)


@router.get(
    "/{organization_id}",
    status_code=status.HTTP_200_OK,
    summary="Get an organization across the server",
    responses=AUTH_ERROR_RESPONSES | ORGANIZATION_NOT_FOUND_RESPONSE,
)
async def get_organization(
    organization_id: OrganizationIdPath,
    organizations_service: OperatorOrganizationsServiceDep,
    _operator_ctx: OperatorOrganizationsReadDep,
) -> OperatorOrganizationResponse:
    """Retrieve one organization through the server-operator control plane."""
    result = await organizations_service.get(
        organization_id=parse_organization_id(organization_id)
    )
    return OperatorOrganizationResponse(name=result.name, public_id=result.public_id)


@router.patch(
    "/{organization_id}",
    status_code=status.HTTP_200_OK,
    summary="Patch an organization across the server",
    responses=(
        WRITE_AUTH_ERROR_RESPONSES
        | ORGANIZATION_NOT_FOUND_RESPONSE
        | ORGANIZATION_CONFLICT_RESPONSE
    ),
)
async def patch_organization(
    organization_id: OrganizationIdPath,
    payload: OperatorOrganizationPatchRequest,
    organizations_service: OperatorOrganizationsServiceDep,
    _operator_ctx: OperatorOrganizationsWriteDep,
) -> OperatorOrganizationResponse:
    """Patch one organization through the server-operator control plane."""
    dto = OrganizationUpdateDTO(name=payload.name)
    result = await organizations_service.update(
        organization_id=parse_organization_id(organization_id),
        dto=dto,
    )
    return OperatorOrganizationResponse(name=result.name, public_id=result.public_id)

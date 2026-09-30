"""Server-wide organization administration API routes."""

from typing import Annotated

from fastapi import APIRouter, Security, status

from app.api.dependencies.ids import OrganizationIdPath
from app.api.error_responses import app_error_responses
from app.api.schemas import PaginatedResponse
from app.api.v1.server.organizations.mapping import server_organization_response
from app.api.v1.server.organizations.schemas import (
    ServerOrganizationCreateRequest,
    ServerOrganizationListQueryDep,
    ServerOrganizationPatchRequest,
    ServerOrganizationResponse,
)
from app.browser_sessions.errors import (
    BrowserSessionInvalidError,
    CSRF_ERRORS,
)
from app.core.errors.common import (
    ForbiddenOperationError,
    ObjectNotFoundError,
    UnauthorizedError,
)
from app.db.errors import CheckViolationError
from app.identity.dependencies import ServerOrganizationsServiceDep
from app.identity.organizations.dtos import OrganizationCreateDTO, OrganizationUpdateDTO
from app.security.authorization import require_operator_permission
from app.security.permissions import Permission
from app.security.principals import UserPrincipalContext


router = APIRouter(prefix="/organizations")
OrganizationListResponse = PaginatedResponse[ServerOrganizationResponse]
AUTH_ERROR_RESPONSES = app_error_responses(
    UnauthorizedError,
    BrowserSessionInvalidError,
    ForbiddenOperationError,
    descriptions={
        401: "Authentication is missing or invalid.",
        403: "Server-operator authority or the required scope is missing.",
    },
)
WRITE_AUTH_ERROR_RESPONSES = app_error_responses(
    UnauthorizedError,
    BrowserSessionInvalidError,
    ForbiddenOperationError,
    *CSRF_ERRORS,
    descriptions={
        401: "Authentication is missing or invalid.",
        403: (
            "Server-operator authority or the required scope is missing, or a "
            "browser-session request lacks valid CSRF proof."
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
ServerOrganizationsReadDep = Annotated[
    UserPrincipalContext,
    Security(
        require_operator_permission(Permission.ORGANIZATIONS_READ),
        scopes=[Permission.ORGANIZATIONS_READ.value],
    ),
]
ServerOrganizationsWriteDep = Annotated[
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
    organizations_service: ServerOrganizationsServiceDep,
    _operator_ctx: ServerOrganizationsReadDep,
    query: ServerOrganizationListQueryDep,
) -> OrganizationListResponse:
    """List organizations through the server control plane."""
    results = await organizations_service.list(offset=query.offset, limit=query.limit)
    total = await organizations_service.count()
    return OrganizationListResponse(
        items=[server_organization_response(result) for result in results],
        offset=query.offset,
        limit=query.limit,
        total=total,
    )


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    summary="Create an organization across the server",
    responses=WRITE_AUTH_ERROR_RESPONSES | ORGANIZATION_CONFLICT_RESPONSE,
)
async def create_organization(
    payload: ServerOrganizationCreateRequest,
    organizations_service: ServerOrganizationsServiceDep,
    _operator_ctx: ServerOrganizationsWriteDep,
) -> ServerOrganizationResponse:
    """Create an organization through the server control plane."""
    dto = OrganizationCreateDTO(name=payload.name)
    result = await organizations_service.create(dto=dto)
    return server_organization_response(result)


@router.get(
    "/{organization_id}",
    status_code=status.HTTP_200_OK,
    summary="Get an organization across the server",
    responses=AUTH_ERROR_RESPONSES | ORGANIZATION_NOT_FOUND_RESPONSE,
)
async def get_organization(
    organization_id: OrganizationIdPath,
    organizations_service: ServerOrganizationsServiceDep,
    _operator_ctx: ServerOrganizationsReadDep,
) -> ServerOrganizationResponse:
    """Retrieve one organization through the server control plane."""
    result = await organizations_service.get(organization_id=organization_id)
    return server_organization_response(result)


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
    payload: ServerOrganizationPatchRequest,
    organizations_service: ServerOrganizationsServiceDep,
    _operator_ctx: ServerOrganizationsWriteDep,
) -> ServerOrganizationResponse:
    """Patch one organization through the server control plane."""
    dto = OrganizationUpdateDTO(name=payload.name)
    result = await organizations_service.update(
        organization_id=organization_id,
        dto=dto,
    )
    return server_organization_response(result)

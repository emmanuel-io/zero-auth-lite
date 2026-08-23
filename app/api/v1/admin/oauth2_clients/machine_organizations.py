"""Machine-organization access administration for OAuth2 clients."""

from fastapi import APIRouter, status

from app.api.v1.admin.oauth2_clients.contract import (
    AUTH_ERROR_RESPONSES,
    CLIENT_CONFLICT_RESPONSE,
    CLIENT_NOT_FOUND_RESPONSE,
    INVALID_CLIENT_RESPONSE,
    OAUTH2_CLIENTS_PREFIX,
    OAuth2ClientIdPath,
    OperatorOAuth2ClientsReadDep,
    OperatorOAuth2ClientsWriteDep,
    WRITE_AUTH_ERROR_RESPONSES,
)
from app.api.v1.admin.oauth2_clients.errors import (
    raise_oauth2_client_service_error,
)
from app.api.v1.admin.oauth2_clients.organization_schemas import (
    OAuth2ClientMachineOrganizationAccessRequest,
    OAuth2ClientMachineOrganizationAccessResponse,
)
from app.oauth2.clients.dtos import (
    OAuth2ClientMachineOrganizationsDTO,
    OAuth2ClientMachineOrganizationUpdateDTO,
)
from app.oauth2.clients.management.dependencies import (
    OAuth2ClientMachineOrganizationAccessServiceDep,
)
from app.oauth2.clients.management.errors import OAuth2ClientServiceError


def machine_organizations_response(
    dto: OAuth2ClientMachineOrganizationsDTO,
) -> OAuth2ClientMachineOrganizationAccessResponse:
    """Convert a machine-organization policy DTO to its HTTP response."""
    return OAuth2ClientMachineOrganizationAccessResponse.model_validate(
        dto, from_attributes=True
    )


router = APIRouter(prefix=OAUTH2_CLIENTS_PREFIX)


@router.get(
    "/{client_id}/machine-organizations",
    status_code=status.HTTP_200_OK,
    summary="List a global OAuth2 client's machine organization access",
    responses=AUTH_ERROR_RESPONSES | CLIENT_NOT_FOUND_RESPONSE,
)
async def list_oauth2_client_machine_organizations(
    client_id: OAuth2ClientIdPath,
    service: OAuth2ClientMachineOrganizationAccessServiceDep,
    operator_ctx: OperatorOAuth2ClientsReadDep,
) -> OAuth2ClientMachineOrganizationAccessResponse:
    """List the stateful organization policy used by machine principals."""
    try:
        result = await service.list_machine_organizations(
            client_id=client_id, operator_ctx=operator_ctx
        )
        return machine_organizations_response(result)
    except OAuth2ClientServiceError as exc:
        raise_oauth2_client_service_error(exc)


@router.put(
    "/{client_id}/machine-organizations",
    status_code=status.HTTP_200_OK,
    summary="Replace a global OAuth2 client's machine organization access",
    responses=WRITE_AUTH_ERROR_RESPONSES
    | INVALID_CLIENT_RESPONSE
    | CLIENT_NOT_FOUND_RESPONSE
    | CLIENT_CONFLICT_RESPONSE,
)
async def replace_oauth2_client_machine_organizations(
    client_id: OAuth2ClientIdPath,
    payload: OAuth2ClientMachineOrganizationAccessRequest,
    service: OAuth2ClientMachineOrganizationAccessServiceDep,
    operator_ctx: OperatorOAuth2ClientsWriteDep,
) -> OAuth2ClientMachineOrganizationAccessResponse:
    """Atomically replace machine access mode and organization assignments."""
    dto = OAuth2ClientMachineOrganizationUpdateDTO(**payload.model_dump())
    try:
        result = await service.replace_machine_organization_access(
            client_id=client_id,
            dto=dto,
            operator_ctx=operator_ctx,
        )
        return machine_organizations_response(result)
    except OAuth2ClientServiceError as exc:
        raise_oauth2_client_service_error(exc)

"""User-organization access administration for OAuth2 clients."""

from fastapi import APIRouter, status

from app.api.v1.server.oauth2_clients.dependencies import (
    OperatorOAuth2ClientsReadDep,
    OperatorOAuth2ClientsWriteDep,
)
from app.api.v1.server.oauth2_clients.mapping import user_organizations_response
from app.api.v1.server.oauth2_clients.openapi_responses import (
    AUTH_ERROR_RESPONSES,
    CLIENT_CONFLICT_RESPONSE,
    CLIENT_NOT_FOUND_RESPONSE,
    INVALID_CLIENT_RESPONSE,
    WRITE_AUTH_ERROR_RESPONSES,
)
from app.api.v1.server.oauth2_clients.paths import (
    OAUTH2_CLIENTS_PREFIX,
    OAuth2ClientIdPath,
)
from app.api.v1.server.oauth2_clients.schemas import (
    OAuth2ClientUserOrganizationsRequest,
    OAuth2ClientUserOrganizationsResponse,
)
from app.oauth2.clients.dtos import OAuth2ClientUserOrganizationUpdateDTO
from app.oauth2.clients.management.app_errors import (
    raise_oauth2_client_management_error,
)
from app.oauth2.clients.management.dependencies import (
    OAuth2ClientUserOrganizationAccessServiceDep,
)
from app.oauth2.clients.management.errors import OAuth2ClientServiceError


router = APIRouter(prefix=OAUTH2_CLIENTS_PREFIX)


@router.get(
    "/{client_id}/user-organizations",
    status_code=status.HTTP_200_OK,
    summary="List a global OAuth2 client's allowed user organizations",
    responses=AUTH_ERROR_RESPONSES | CLIENT_NOT_FOUND_RESPONSE,
)
async def list_oauth2_client_user_organizations(
    client_id: OAuth2ClientIdPath,
    service: OAuth2ClientUserOrganizationAccessServiceDep,
    operator_ctx: OperatorOAuth2ClientsReadDep,
) -> OAuth2ClientUserOrganizationsResponse:
    """List user organizations explicitly assigned by the server operator."""
    try:
        return user_organizations_response(
            await service.list_user_organizations(
                client_id=client_id, operator_ctx=operator_ctx
            )
        )
    except OAuth2ClientServiceError as exc:
        raise_oauth2_client_management_error(exc)


@router.put(
    "/{client_id}/user-organizations",
    status_code=status.HTTP_200_OK,
    summary="Replace a global OAuth2 client's allowed user organizations",
    responses=WRITE_AUTH_ERROR_RESPONSES
    | INVALID_CLIENT_RESPONSE
    | CLIENT_NOT_FOUND_RESPONSE
    | CLIENT_CONFLICT_RESPONSE,
)
async def replace_oauth2_client_user_organizations(
    client_id: OAuth2ClientIdPath,
    payload: OAuth2ClientUserOrganizationsRequest,
    service: OAuth2ClientUserOrganizationAccessServiceDep,
    operator_ctx: OperatorOAuth2ClientsWriteDep,
) -> OAuth2ClientUserOrganizationsResponse:
    """Atomically replace user organizations explicitly assigned by an operator."""
    try:
        result = await service.replace_user_organizations(
            client_id=client_id,
            dto=OAuth2ClientUserOrganizationUpdateDTO(**payload.model_dump()),
            operator_ctx=operator_ctx,
        )
        return user_organizations_response(result)
    except OAuth2ClientServiceError as exc:
        raise_oauth2_client_management_error(exc)

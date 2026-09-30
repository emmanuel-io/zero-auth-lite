"""Global OAuth2 client registry administration routes."""

from fastapi import APIRouter, Response, status

from app.api.schemas import PaginatedResponse
from app.api.v1.server.oauth2_clients.dependencies import (
    OperatorOAuth2ClientsReadDep,
    OperatorOAuth2ClientsWriteDep,
)
from app.api.v1.server.oauth2_clients.mapping import (
    client_create_response,
    client_registration_dto,
    client_replace_dto,
    client_response,
)
from app.api.v1.server.oauth2_clients.openapi_responses import (
    AUTH_ERROR_RESPONSES,
    CLIENT_CONFLICT_RESPONSE,
    CLIENT_NOT_FOUND_RESPONSE,
    CREATE_CLIENT_RESPONSES,
    INVALID_CLIENT_RESPONSE,
    WRITE_AUTH_ERROR_RESPONSES,
)
from app.api.v1.server.oauth2_clients.paths import (
    OAUTH2_CLIENTS_PREFIX,
    OAuth2ClientIdPath,
)
from app.api.v1.server.oauth2_clients.schemas import (
    OAuth2ClientCreateRequest,
    OAuth2ClientCreateResponse,
    OAuth2ClientListQueryDep,
    OAuth2ClientReadResponse,
    OAuth2ClientReplaceRequest,
)
from app.oauth2.clients.management.app_errors import (
    raise_oauth2_client_management_error,
)
from app.oauth2.clients.management.dependencies import (
    OAuth2ClientRegistrationServiceDep,
    OAuth2ClientRegistryServiceDep,
)
from app.oauth2.clients.management.errors import OAuth2ClientServiceError


router = APIRouter(prefix=OAUTH2_CLIENTS_PREFIX)
OAuth2ClientListResponse = PaginatedResponse[OAuth2ClientReadResponse]


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    summary="Create a global OAuth2 client",
    description=(
        "Create a global OAuth2 client. Confidential clients receive their raw "
        "secret only in this response; it cannot be retrieved later."
    ),
    responses=CREATE_CLIENT_RESPONSES,
)
async def create_oauth2_client(
    response: Response,
    payload: OAuth2ClientCreateRequest,
    service: OAuth2ClientRegistrationServiceDep,
    operator_ctx: OperatorOAuth2ClientsWriteDep,
) -> OAuth2ClientCreateResponse:
    """Create a global OAuth2 client through the server control plane."""
    try:
        result = await service.create_client(
            dto=client_registration_dto(payload), operator_ctx=operator_ctx
        )
    except OAuth2ClientServiceError as exc:
        raise_oauth2_client_management_error(exc)
    if result.client_secret is not None:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    return client_create_response(result)


@router.get(
    "",
    status_code=status.HTTP_200_OK,
    summary="List global OAuth2 clients",
    responses=AUTH_ERROR_RESPONSES,
)
async def list_oauth2_clients(
    service: OAuth2ClientRegistryServiceDep,
    operator_ctx: OperatorOAuth2ClientsReadDep,
    query: OAuth2ClientListQueryDep,
) -> OAuth2ClientListResponse:
    """List global OAuth2 clients through the server control plane."""
    items = await service.list_clients(
        operator_ctx=operator_ctx, offset=query.offset, limit=query.limit
    )
    total = await service.count_clients(operator_ctx=operator_ctx)
    return OAuth2ClientListResponse(
        items=[client_response(item) for item in items],
        offset=query.offset,
        limit=query.limit,
        total=total,
    )


@router.get(
    "/{client_id}",
    status_code=status.HTTP_200_OK,
    summary="Get one global OAuth2 client",
    responses=AUTH_ERROR_RESPONSES | CLIENT_NOT_FOUND_RESPONSE,
)
async def read_oauth2_client(
    client_id: OAuth2ClientIdPath,
    service: OAuth2ClientRegistryServiceDep,
    operator_ctx: OperatorOAuth2ClientsReadDep,
) -> OAuth2ClientReadResponse:
    """Read one global OAuth2 client through the server control plane."""
    try:
        return client_response(
            await service.read_client(client_id=client_id, operator_ctx=operator_ctx)
        )
    except OAuth2ClientServiceError as exc:
        raise_oauth2_client_management_error(exc)


@router.put(
    "/{client_id}",
    status_code=status.HTTP_200_OK,
    summary="Replace one global OAuth2 client",
    responses=WRITE_AUTH_ERROR_RESPONSES
    | INVALID_CLIENT_RESPONSE
    | CLIENT_NOT_FOUND_RESPONSE
    | CLIENT_CONFLICT_RESPONSE,
)
async def replace_oauth2_client(
    client_id: OAuth2ClientIdPath,
    payload: OAuth2ClientReplaceRequest,
    service: OAuth2ClientRegistryServiceDep,
    operator_ctx: OperatorOAuth2ClientsWriteDep,
) -> OAuth2ClientReadResponse:
    """Replace one global OAuth2 client through the server control plane."""
    try:
        result = await service.replace_client(
            client_id=client_id,
            dto=client_replace_dto(payload),
            operator_ctx=operator_ctx,
        )
        return client_response(result)
    except OAuth2ClientServiceError as exc:
        raise_oauth2_client_management_error(exc)


@router.delete(
    "/{client_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete one global OAuth2 client",
    responses=WRITE_AUTH_ERROR_RESPONSES | CLIENT_NOT_FOUND_RESPONSE,
)
async def delete_oauth2_client(
    client_id: OAuth2ClientIdPath,
    service: OAuth2ClientRegistryServiceDep,
    operator_ctx: OperatorOAuth2ClientsWriteDep,
) -> Response:
    """Delete one global OAuth2 client through the server control plane."""
    try:
        await service.delete_client(client_id=client_id, operator_ctx=operator_ctx)
    except OAuth2ClientServiceError as exc:
        raise_oauth2_client_management_error(exc)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

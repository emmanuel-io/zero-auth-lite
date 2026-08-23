"""OAuth2 client credential rotation administration route."""

from fastapi import APIRouter, Response, status

from app.api.v1.admin.oauth2_clients.contract import (
    OAUTH2_CLIENTS_PREFIX,
    OAuth2ClientIdPath,
    OperatorOAuth2ClientsWriteDep,
    ROTATE_SECRET_RESPONSES,
)
from app.api.v1.admin.oauth2_clients.credential_schemas import (
    OAuth2ClientSecretResponse,
)
from app.api.v1.admin.oauth2_clients.errors import (
    raise_oauth2_client_service_error,
)
from app.oauth2.clients.management.dependencies import (
    OAuth2ClientCredentialRotationServiceDep,
)
from app.oauth2.clients.management.errors import OAuth2ClientServiceError


router = APIRouter(prefix=OAUTH2_CLIENTS_PREFIX)


@router.post(
    "/{client_id}/secrets",
    status_code=status.HTTP_200_OK,
    summary="Rotate a global OAuth2 client secret",
    description=(
        "Replace a confidential client's secret. The raw replacement is returned only "
        "once and cannot be retrieved later."
    ),
    responses=ROTATE_SECRET_RESPONSES,
)
async def create_oauth2_client_secret(
    response: Response,
    client_id: OAuth2ClientIdPath,
    service: OAuth2ClientCredentialRotationServiceDep,
    operator_ctx: OperatorOAuth2ClientsWriteDep,
) -> OAuth2ClientSecretResponse:
    """Rotate one global confidential client secret."""
    try:
        result = await service.create_client_secret(
            client_id=client_id, operator_ctx=operator_ctx
        )
    except OAuth2ClientServiceError as exc:
        raise_oauth2_client_service_error(exc)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    return OAuth2ClientSecretResponse(
        client_id=result.client_id,
        client_secret=result.client_secret,
    )

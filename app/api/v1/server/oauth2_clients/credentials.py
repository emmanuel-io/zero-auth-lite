"""OAuth2 client credential rotation administration route."""

from fastapi import APIRouter, Response, status

from app.api.v1.server.oauth2_clients.dependencies import (
    OperatorOAuth2ClientsWriteDep,
)
from app.api.v1.server.oauth2_clients.mapping import client_secret_response
from app.api.v1.server.oauth2_clients.openapi_responses import (
    ROTATE_SECRET_RESPONSES,
)
from app.api.v1.server.oauth2_clients.paths import (
    OAUTH2_CLIENTS_PREFIX,
    OAuth2ClientIdPath,
)
from app.api.v1.server.oauth2_clients.schemas import (
    OAuth2ClientSecretResponse,
)
from app.oauth2.clients.management.app_errors import (
    raise_oauth2_client_management_error,
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
        "once and cannot be retrieved later. Existing OAuth2 sessions and tokens "
        "remain valid until expiry or explicit revocation."
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
        result = await service.rotate_client_secret_autonomously(
            client_id=client_id, operator_ctx=operator_ctx
        )
    except OAuth2ClientServiceError as exc:
        raise_oauth2_client_management_error(exc)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    return client_secret_response(result)

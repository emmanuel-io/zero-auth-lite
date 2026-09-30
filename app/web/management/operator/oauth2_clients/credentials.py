"""OAuth2 client credential management actions."""

from fastapi import APIRouter, Request, Response

from app.browser_sessions.service_dependencies import BrowserSessionLifecycleServiceDep
from app.oauth2.clients.management.dependencies import (
    OAuth2ClientCredentialRotationServiceDep,
)
from app.oauth2.clients.management.errors import OAuth2ClientServiceError
from app.web.management.dependencies import OperatorFormDep
from app.web.management.errors import raise_management_oauth2_client_error
from app.web.management.forms import ConfirmedFormDep
from app.web.management.ids import OAuth2ClientIdPath
from app.web.management.responses import render_management_page
from app.web.routes import ManagementPageRoute


router = APIRouter(route_class=ManagementPageRoute)


@router.post("/oauth2/clients/{client_id}/rotate-secret")
async def rotate_secret(
    client_id: OAuth2ClientIdPath,
    request: Request,
    service: OAuth2ClientCredentialRotationServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OperatorFormDep,
    _confirmation: ConfirmedFormDep,
) -> Response:
    """Rotate the selected OAuth2 client secret."""
    try:
        result = await service.rotate_client_secret_autonomously(
            client_id=client_id, operator_ctx=user_ctx
        )
    except OAuth2ClientServiceError as exc:
        raise_management_oauth2_client_error(exc)
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/operator/client_secret.html",
        client=result,
        client_secret=result.client_secret,
        notice=None,
    )

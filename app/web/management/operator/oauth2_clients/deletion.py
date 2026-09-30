"""OAuth2 client deletion pages and actions."""

from fastapi import APIRouter, Request, Response

from app.browser_sessions.service_dependencies import BrowserSessionLifecycleServiceDep
from app.oauth2.clients.management.dependencies import OAuth2ClientRegistryServiceDep
from app.oauth2.clients.management.errors import OAuth2ClientServiceError
from app.web.management.dependencies import OperatorFormDep, OperatorUIDep
from app.web.management.errors import raise_management_oauth2_client_error
from app.web.management.forms import ConfirmedFormDep
from app.web.management.ids import OAuth2ClientIdPath
from app.web.management.notices import ManagementNotice
from app.web.management.responses import mutation_success, render_management_page
from app.web.routes import ManagementPageRoute


router = APIRouter(route_class=ManagementPageRoute)


@router.get("/oauth2/clients/{client_id}/delete")
async def confirm_delete_client(
    client_id: OAuth2ClientIdPath,
    request: Request,
    service: OAuth2ClientRegistryServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OperatorUIDep,
) -> Response:
    """Render the OAuth2 client-deletion confirmation."""
    try:
        client = await service.read_client(client_id=client_id, operator_ctx=user_ctx)
    except OAuth2ClientServiceError as exc:
        raise_management_oauth2_client_error(exc)
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/confirm.html",
        heading="Delete OAuth2 client?",
        message=f"This permanently deletes {client.name} ({client_id}).",
        action=f"/management/operator/oauth2/clients/{client_id}/delete",
        cancel_url=f"/management/operator/oauth2/clients/{client_id}",
        submit_label="Delete client",
    )


@router.post("/oauth2/clients/{client_id}/delete")
async def delete_client(
    client_id: OAuth2ClientIdPath,
    request: Request,
    service: OAuth2ClientRegistryServiceDep,
    user_ctx: OperatorFormDep,
    _confirmation: ConfirmedFormDep,
) -> Response:
    """Delete the selected OAuth2 client."""
    try:
        await service.delete_client(client_id=client_id, operator_ctx=user_ctx)
    except OAuth2ClientServiceError as exc:
        raise_management_oauth2_client_error(exc)
    return mutation_success(
        request,
        "/management/operator/oauth2/clients",
        notice=ManagementNotice.CLIENT_DELETED,
    )

"""OAuth2 client registry management pages."""

from typing import Annotated

from fastapi import APIRouter, Form, Query, Request, Response

from app.browser_sessions.service_dependencies import BrowserSessionLifecycleServiceDep
from app.oauth2.clients.dtos import (
    OAuth2ClientRegistrationDTO,
    OAuth2ClientRegistryReplaceDTO,
)
from app.oauth2.clients.management.dependencies import (
    OAuth2ClientMachineOrganizationAccessServiceDep,
    OAuth2ClientRegistrationServiceDep,
    OAuth2ClientRegistryServiceDep,
    OAuth2ClientUserOrganizationAccessServiceDep,
)
from app.oauth2.clients.management.errors import OAuth2ClientServiceError
from app.web.management.dependencies import OperatorFormDep, OperatorUIDep
from app.web.management.errors import raise_management_oauth2_client_error
from app.web.management.forms import split_non_empty_lines
from app.web.management.ids import OAuth2ClientIdPath
from app.web.management.notices import ManagementNotice
from app.web.management.operator.forms import (
    OAuth2ClientRegistrationForm,
    OAuth2ClientReplacementForm,
)
from app.web.management.operator.views import OAuth2ClientView
from app.web.management.pagination import page_url
from app.web.management.responses import mutation_success, render_management_page
from app.web.routes import ManagementPageRoute
from app.web.validation import validated_model


router = APIRouter(route_class=ManagementPageRoute)


@router.get("/oauth2/clients")
async def clients(  # noqa: PLR0913, PLR0917
    request: Request,
    service: OAuth2ClientRegistryServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OperatorUIDep,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    notice: Annotated[str | None, Query()] = None,
) -> Response:
    """Render the OAuth2 client list."""
    try:
        items = await service.list_clients(
            operator_ctx=user_ctx, offset=offset, limit=limit
        )
        total = await service.count_clients(operator_ctx=user_ctx)
    except OAuth2ClientServiceError as exc:
        raise_management_oauth2_client_error(exc)
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/operator/clients.html",
        clients=[OAuth2ClientView.from_dto(item) for item in items],
        total=total,
        previous_url=(
            page_url(
                "/management/operator/oauth2/clients",
                offset=offset - limit,
                limit=limit,
            )
            if offset > 0
            else None
        ),
        next_url=(
            page_url(
                "/management/operator/oauth2/clients",
                offset=offset + limit,
                limit=limit,
            )
            if offset + limit < total
            else None
        ),
        notice=notice,
    )


@router.get("/oauth2/clients/new")
async def new_client(
    request: Request,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OperatorUIDep,
) -> Response:
    """Render the new OAuth2 client form."""
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/operator/client_form.html",
        client=None,
        action="/management/operator/oauth2/clients",
        heading="Register OAuth2 client",
    )


@router.post("/oauth2/clients")
async def create_client(
    request: Request,
    service: OAuth2ClientRegistrationServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OperatorFormDep,
    form: Annotated[OAuth2ClientRegistrationForm, Form()],
) -> Response:
    """Create an OAuth2 client from the submitted form."""
    dto = validated_model(
        OAuth2ClientRegistrationDTO,
        name=form.name,
        grant_types=[grant_type.value for grant_type in form.grant_types],
        scopes=form.scopes.split(),
        redirect_uris=split_non_empty_lines(form.redirect_uris),
        is_confidential=form.is_confidential,
        requires_consent=form.requires_consent,
        is_active=form.is_active,
        user_organization_access=form.user_organization_access,
        user_organization_ids=split_non_empty_lines(form.organization_ids),
    )
    try:
        result = await service.create_client(
            dto=dto,
            operator_ctx=user_ctx,
        )
    except OAuth2ClientServiceError as exc:
        raise_management_oauth2_client_error(exc)
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/operator/client_secret.html",
        client=OAuth2ClientView.from_dto(result.client),
        client_secret=result.client_secret,
        notice=None,
    )


@router.get("/oauth2/clients/{client_id}")
async def client_detail(  # noqa: PLR0913, PLR0917
    client_id: OAuth2ClientIdPath,
    request: Request,
    service: OAuth2ClientRegistryServiceDep,
    user_organizations_service: OAuth2ClientUserOrganizationAccessServiceDep,
    machine_organizations_service: OAuth2ClientMachineOrganizationAccessServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OperatorUIDep,
    notice: Annotated[str | None, Query()] = None,
) -> Response:
    """Render one OAuth2 client management page."""
    try:
        client = await service.read_client(client_id=client_id, operator_ctx=user_ctx)
        user_access = await user_organizations_service.list_user_organizations(
            client_id=client_id, operator_ctx=user_ctx
        )
        machine_access = await machine_organizations_service.list_machine_organizations(
            client_id=client_id, operator_ctx=user_ctx
        )
    except OAuth2ClientServiceError as exc:
        raise_management_oauth2_client_error(exc)
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/operator/client_form.html",
        client=OAuth2ClientView.from_dto(client),
        user_organization_ids=[
            item.organization_id for item in user_access.organizations
        ],
        machine_organization_ids=machine_access.organization_ids,
        action=f"/management/operator/oauth2/clients/{client_id}",
        heading="Manage OAuth2 client",
        notice=notice,
    )


@router.post("/oauth2/clients/{client_id}")
async def update_client(
    client_id: OAuth2ClientIdPath,
    request: Request,
    service: OAuth2ClientRegistryServiceDep,
    user_ctx: OperatorFormDep,
    form: Annotated[OAuth2ClientReplacementForm, Form()],
) -> Response:
    """Update the selected OAuth2 client."""
    dto = validated_model(
        OAuth2ClientRegistryReplaceDTO,
        name=form.name,
        grant_types=[grant_type.value for grant_type in form.grant_types],
        scopes=form.scopes.split(),
        redirect_uris=split_non_empty_lines(form.redirect_uris),
        is_confidential=form.is_confidential,
        requires_consent=form.requires_consent,
        is_active=form.is_active,
    )
    try:
        await service.replace_client(
            client_id=client_id,
            dto=dto,
            operator_ctx=user_ctx,
        )
    except OAuth2ClientServiceError as exc:
        raise_management_oauth2_client_error(exc)
    return mutation_success(
        request,
        f"/management/operator/oauth2/clients/{client_id}",
        notice=ManagementNotice.CLIENT_UPDATED,
    )

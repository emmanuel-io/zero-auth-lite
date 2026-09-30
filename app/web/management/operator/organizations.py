"""Server-operator organization browser routes."""

from typing import Annotated

from fastapi import APIRouter, Form, Query, Request, Response

from app.browser_sessions.service_dependencies import BrowserSessionLifecycleServiceDep
from app.identity.organizations.dtos import OrganizationCreateDTO, OrganizationUpdateDTO
from app.web.management.dependencies import (
    OperatorFormDep,
    OperatorFormOrganizationsServiceDep,
    OperatorUIDep,
    OperatorUIOrganizationsServiceDep,
)
from app.web.management.ids import OrganizationIdPath
from app.web.management.notices import ManagementNotice
from app.web.management.operator.forms import (
    OperatorOrganizationCreateForm,
    OperatorOrganizationUpdateForm,
)
from app.web.management.operator.views import OrganizationView
from app.web.management.pagination import page_url
from app.web.management.responses import mutation_success, render_management_page
from app.web.routes import ManagementPageRoute


router = APIRouter(route_class=ManagementPageRoute)


@router.get("/organizations")
async def organizations(  # noqa: PLR0913, PLR0917
    request: Request,
    service: OperatorUIOrganizationsServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OperatorUIDep,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    notice: Annotated[str | None, Query()] = None,
) -> Response:
    """Render the organization list."""
    items = await service.list(offset=offset, limit=limit)
    total = await service.count()
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/operator/organizations.html",
        organizations=[OrganizationView.from_dto(item) for item in items],
        total=total,
        offset=offset,
        limit=limit,
        previous_url=(
            page_url(
                "/management/operator/organizations",
                offset=offset - limit,
                limit=limit,
            )
            if offset > 0
            else None
        ),
        next_url=(
            page_url(
                "/management/operator/organizations",
                offset=offset + limit,
                limit=limit,
            )
            if offset + limit < total
            else None
        ),
        notice=notice,
    )


@router.post("/organizations")
async def create_organization(
    request: Request,
    service: OperatorFormOrganizationsServiceDep,
    _user_ctx: OperatorFormDep,
    form: Annotated[OperatorOrganizationCreateForm, Form()],
) -> Response:
    """Create an organization from the submitted form."""
    dto = OrganizationCreateDTO(name=form.name)
    result = await service.create(dto=dto)
    return mutation_success(
        request,
        f"/management/operator/organizations/{result.public_id!s}",
        notice=ManagementNotice.ORGANIZATION_CREATED,
    )


@router.get("/organizations/new")
async def new_organization(
    request: Request,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OperatorUIDep,
) -> Response:
    """Render the new-organization form."""
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/operator/organization_form.html",
    )


@router.get("/organizations/{organization_id}")
async def organization_detail(  # noqa: PLR0913, PLR0917
    organization_id: OrganizationIdPath,
    request: Request,
    service: OperatorUIOrganizationsServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OperatorUIDep,
    notice: Annotated[str | None, Query()] = None,
) -> Response:
    """Render one organization management page."""
    organization = await service.get(organization_id=organization_id)
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/operator/organization.html",
        organization=OrganizationView.from_dto(organization),
        notice=notice,
    )


@router.post("/organizations/{organization_id}")
async def update_organization(
    organization_id: OrganizationIdPath,
    request: Request,
    service: OperatorFormOrganizationsServiceDep,
    _user_ctx: OperatorFormDep,
    form: Annotated[OperatorOrganizationUpdateForm, Form()],
) -> Response:
    """Update the selected organization."""
    dto = OrganizationUpdateDTO(name=form.name)
    await service.update(
        organization_id=organization_id,
        dto=dto,
    )
    return mutation_success(
        request,
        f"/management/operator/organizations/{organization_id}",
        notice=ManagementNotice.ORGANIZATION_UPDATED,
    )

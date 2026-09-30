"""Current-organization metadata browser routes."""

from typing import Annotated

from fastapi import APIRouter, Form, Query, Request, Response

from app.browser_sessions.service_dependencies import BrowserSessionLifecycleServiceDep
from app.identity.organizations.dtos import OrganizationUpdateDTO
from app.settings.root import Settings
from app.web.management.dependencies import (
    OrganizationAdminFormDep,
    OrganizationAdminUIDep,
    OrganizationFormMetadataServiceDep,
    OrganizationUIMetadataServiceDep,
)
from app.web.management.notices import ManagementNotice
from app.web.management.organization.forms import OrganizationUpdateForm
from app.web.management.responses import mutation_success, render_management_page
from app.web.routes import ManagementPageRoute


def create_metadata_router(settings: Settings) -> APIRouter:
    """Create current-organization metadata routes."""
    router = APIRouter(route_class=ManagementPageRoute)

    @router.get("", name="organization_ui_dashboard")
    async def dashboard(
        request: Request,
        lifecycle_service: BrowserSessionLifecycleServiceDep,
        user_ctx: OrganizationAdminUIDep,
        notice: Annotated[str | None, Query()] = None,
    ) -> Response:
        """Render the management dashboard."""
        return await render_management_page(
            request,
            lifecycle_service,
            user_ctx,
            "management/organization/dashboard.html",
            oauth2_enabled=settings.oauth2.has_enabled_grants,
            notice=notice,
        )

    @router.get("/settings", name="organization_ui_settings")
    async def organization_settings(
        request: Request,
        organization_service: OrganizationUIMetadataServiceDep,
        lifecycle_service: BrowserSessionLifecycleServiceDep,
        user_ctx: OrganizationAdminUIDep,
    ) -> Response:
        """Show the current-organization metadata form."""
        organization = await organization_service.get()
        return await render_management_page(
            request,
            lifecycle_service,
            user_ctx,
            "management/organization/settings.html",
            organization=organization,
        )

    @router.post("")
    async def update_organization(
        request: Request,
        organization_service: OrganizationFormMetadataServiceDep,
        _user_ctx: OrganizationAdminFormDep,
        form: Annotated[OrganizationUpdateForm, Form()],
    ) -> Response:
        """Update the selected organization."""
        dto = OrganizationUpdateDTO(name=form.name)
        await organization_service.update(dto=dto)
        return mutation_success(
            request,
            "/management/organization",
            notice=ManagementNotice.ORGANIZATION_UPDATED,
        )

    return router

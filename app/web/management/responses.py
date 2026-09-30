"""Shared response behavior for server-rendered management pages."""

from dataclasses import dataclass
from urllib.parse import urlencode

from fastapi import Request, Response, status
from starlette.responses import HTMLResponse

from app.browser_sessions.service_dependencies import BrowserSessionLifecycleServiceDep
from app.security.principals import BrowserUserPrincipalContext
from app.security.roles import Role
from app.settings.state import get_settings_snapshot
from app.web.management.notices import management_notice_text, ManagementNotice
from app.web.redirects import (
    management_authentication_entry_url,
    management_logout_entry_url,
)
from app.web.rendering import no_store_redirect, render_page


@dataclass(frozen=True, slots=True)
class UserDeleteConfirmation:
    """Presentation values for a managed-user deletion confirmation."""

    title: str
    email: str
    action: str
    cancel_url: str


def is_htmx(request: Request) -> bool:
    """Return whether htmx initiated the request."""
    return request.headers.get("HX-Request", "").casefold() == "true"


def management_shell_navigation(request: Request) -> dict[str, str]:
    """Return navigation shared by full management pages and error pages."""
    settings = get_settings_snapshot(request.app)
    return {
        "management_home_url": "/management",
        "logout_url": management_logout_entry_url(settings),
    }


async def render_management_page(
    request: Request,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: BrowserUserPrincipalContext,
    template_name: str,
    *,
    status_code: int = status.HTTP_200_OK,
    **context: object,
) -> HTMLResponse:
    """Render a management page with session CSRF and shared role navigation."""
    csrf_token = await lifecycle_service.get_session_csrf(
        session_id=user_ctx.raw_session_id
    )
    settings = get_settings_snapshot(request.app)
    notice = management_notice_text(context.pop("notice", None))
    return render_page(
        request,
        template_name,
        status_code=status_code,
        csrf_token=csrf_token,
        current_roles=user_ctx.roles,
        current_user_name=user_ctx.display_name,
        current_organization_name=user_ctx.organization_name,
        show_organization_ui=(
            settings.ui.organization_admin_enabled
            and Role.ORGANIZATION_ADMIN in user_ctx.roles
        ),
        show_operator_ui=settings.ui.operator_enabled and user_ctx.is_operator,
        **management_shell_navigation(request),
        fragment=is_htmx(request),
        notice=notice,
        **context,
    )


async def render_user_delete_confirmation(
    request: Request,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: BrowserUserPrincipalContext,
    confirmation: UserDeleteConfirmation,
) -> HTMLResponse:
    """Render the shared confirmation page for deleting a managed user."""
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/confirm.html",
        heading=confirmation.title,
        message=f"This permanently deletes {confirmation.email}.",
        action=confirmation.action,
        cancel_url=confirmation.cancel_url,
        submit_label="Delete user",
    )


def mutation_success(
    request: Request, destination: str, *, notice: ManagementNotice | None = None
) -> Response:
    """Use PRG for ordinary forms and a full safe navigation for htmx forms."""
    if notice is not None:
        separator = "&" if "?" in destination else "?"
        destination = f"{destination}{separator}{urlencode({'notice': notice.value})}"
    return full_navigation(request, destination)


def full_navigation(request: Request, destination: str) -> Response:
    """Navigate the whole browser for ordinary and htmx requests."""
    if is_htmx(request):
        return Response(
            status_code=status.HTTP_204_NO_CONTENT,
            headers={
                "Cache-Control": "no-store",
                "HX-Redirect": destination,
                "Pragma": "no-cache",
            },
        )
    return no_store_redirect(destination)


def authentication_navigation_url(request: Request) -> str:
    """Return the configured authentication entry point for management flows."""
    return management_authentication_entry_url(get_settings_snapshot(request.app))

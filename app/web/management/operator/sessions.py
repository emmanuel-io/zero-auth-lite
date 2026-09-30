"""Server-operator security-session maintenance routes."""

from typing import Annotated

from fastapi import APIRouter, Query, Request, Response

from app.browser_sessions.enums import BrowserSessionRevocationReason
from app.browser_sessions.response_transport import (
    request_session_cookie_clear_on_success,
)
from app.browser_sessions.service_dependencies import (
    BrowserSessionLifecycleServiceDep,
    BrowserSessionRevocationServiceDep,
)
from app.security.session_revocation_dependencies import SecuritySessionRevocationDep
from app.web.management.dependencies import OperatorFormDep, OperatorUIDep
from app.web.management.forms import ConfirmedFormDep
from app.web.management.notices import ManagementNotice
from app.web.management.responses import (
    authentication_navigation_url,
    mutation_success,
    render_management_page,
)
from app.web.routes import ManagementPageRoute


router = APIRouter(route_class=ManagementPageRoute)


@router.get("/sessions")
async def sessions(
    request: Request,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OperatorUIDep,
    notice: Annotated[str | None, Query()] = None,
) -> Response:
    """Render the server-wide security-session page."""
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/operator/sessions.html",
        notice=notice,
    )


@router.post("/sessions/cleanup")
async def cleanup_sessions(
    request: Request,
    service: BrowserSessionRevocationServiceDep,
    _user_ctx: OperatorFormDep,
    _confirmation: ConfirmedFormDep,
) -> Response:
    """Delete expired persisted sessions."""
    await service.cleanup_terminal_sessions()
    return mutation_success(
        request,
        "/management/operator/sessions",
        notice=ManagementNotice.INACTIVE_SESSIONS_DELETED,
    )


@router.get("/sessions/browser/delete")
async def confirm_delete_all_browser_sessions(
    request: Request,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OperatorUIDep,
) -> Response:
    """Render the global browser-session deletion confirmation."""
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/confirm.html",
        heading="Delete all browser sessions?",
        message=(
            "This permanently deletes every browser session across the entire "
            "server. Your current operator session also ends. OAuth2 sessions "
            "are not affected."
        ),
        action="/management/operator/sessions/browser/delete",
        cancel_url="/management/operator/sessions",
        submit_label="Delete all browser sessions",
    )


@router.post("/sessions/browser/delete")
async def delete_all_browser_sessions(
    request: Request,
    service: BrowserSessionRevocationServiceDep,
    _user_ctx: OperatorFormDep,
    _confirmation: ConfirmedFormDep,
) -> Response:
    """Delete every browser session."""
    await service.delete_all_sessions()
    request_session_cookie_clear_on_success(request)
    return mutation_success(
        request,
        authentication_navigation_url(request),
        notice=ManagementNotice.BROWSER_SESSIONS_DELETED,
    )


@router.get("/sessions/oauth2/delete")
async def confirm_delete_all_oauth2_sessions(
    request: Request,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OperatorUIDep,
) -> Response:
    """Render the global OAuth2-session deletion confirmation."""
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/confirm.html",
        heading="Delete all OAuth2 sessions?",
        message=(
            "This permanently deletes every OAuth2 session family and its "
            "tokens across the entire server. Browser sessions are not affected."
        ),
        action="/management/operator/sessions/oauth2/delete",
        cancel_url="/management/operator/sessions",
        submit_label="Delete all OAuth2 sessions",
    )


@router.post("/sessions/oauth2/delete")
async def delete_all_oauth2_sessions(
    request: Request,
    service: SecuritySessionRevocationDep,
    _user_ctx: OperatorFormDep,
    _confirmation: ConfirmedFormDep,
) -> Response:
    """Delete every OAuth2 session."""
    await service.clear_all_oauth2_sessions()
    return mutation_success(
        request,
        "/management/operator/sessions",
        notice=ManagementNotice.OAUTH2_SESSIONS_DELETED,
    )


@router.get("/sessions/revoke")
async def confirm_revoke_all_sessions(
    request: Request,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OperatorUIDep,
) -> Response:
    """Render the global session-revocation confirmation."""
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/confirm.html",
        heading="Revoke all server sessions?",
        message=(
            "This ends every browser and OAuth2 session across the entire "
            "server. Your current operator session also ends."
        ),
        action="/management/operator/sessions/revoke",
        cancel_url="/management/operator/sessions",
        submit_label="Revoke all sessions",
    )


@router.post("/sessions/revoke")
async def revoke_all_sessions(
    request: Request,
    service: SecuritySessionRevocationDep,
    _user_ctx: OperatorFormDep,
    _confirmation: ConfirmedFormDep,
) -> Response:
    """Revoke every browser and OAuth2 session."""
    await service.revoke_all_security_sessions(
        browser_reason=BrowserSessionRevocationReason.SERVER_SESSIONS_REVOKED
    )
    request_session_cookie_clear_on_success(request)
    return mutation_success(
        request,
        authentication_navigation_url(request),
        notice=ManagementNotice.SERVER_SESSIONS_REVOKED,
    )

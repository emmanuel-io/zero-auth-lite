"""Dependency injection for the session based authentication service.

The service supports HttpOnly cookie sessions and scoped CSRF tokens.
"""

from typing import Annotated, TYPE_CHECKING

from fastapi import Depends, Request, Security

from app.browser_sessions.cookies import get_session_cookie
from app.browser_sessions.csrf import CSRF_UNSAFE_METHODS, validate_request_origin
from app.browser_sessions.dtos import BrowserSessionReadDTO
from app.browser_sessions.enums import CSRFPattern
from app.browser_sessions.errors import (
    BrowserSessionInvalidError,
    CSRFCookieHeaderMismatchError,
    CSRFHeaderSessionMismatchError,
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
)
from app.browser_sessions.lifecycle import (
    BrowserSessionLifecycleService,
    remaining_session_lifetime_seconds,
)
from app.browser_sessions.response_transport import (
    request_session_cookie_clear_always,
    request_session_cookie_refresh,
)
from app.browser_sessions.service_dependencies import (
    BrowserSessionLifecycleServiceDep,
)
from app.core.compare import constant_time_equals
from app.security.openapi import cookie_sid
from app.security.principals import BrowserUserPrincipalContext
from app.security.roles import Role
from app.settings.dependencies import BrowserSessionSettingsDep, CSRFSettingsDep


if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.settings.root import Settings


RESOLVED_BROWSER_SESSION_STATE_KEY = "resolved_browser_session"


def get_resolved_browser_session(request: Request) -> BrowserSessionReadDTO | None:
    """Return session state produced by the request's canonical resolver."""
    value = getattr(request.state, RESOLVED_BROWSER_SESSION_STATE_KEY, None)
    return value if isinstance(value, BrowserSessionReadDTO) else None


def _validate_resolved_session_csrf(
    *,
    request: Request,
    csrf_settings: CSRFSettingsDep,
    submitted_token: str | None,
    session_token: str,
) -> None:
    """Validate request CSRF only after browser authority is known to be valid."""
    validate_request_origin(request=request, csrf_settings=csrf_settings)
    if not submitted_token:
        raise CSRFMissingHeaderError
    if csrf_settings.pattern == CSRFPattern.DOUBLE_SUBMIT:
        cookie_token = request.cookies.get(csrf_settings.cookie_name)
        if cookie_token is None:
            raise CSRFMissingCookieError
        if not constant_time_equals(cookie_token, submitted_token):
            raise CSRFCookieHeaderMismatchError
        return
    if not constant_time_equals(submitted_token, session_token):
        raise CSRFHeaderSessionMismatchError


BrowserSessionCookieDep = Annotated[str | None, Security(cookie_sid)]


async def _resolve_browser_user_context(  # noqa: PLR0913
    request: Request,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    csrf_settings: CSRFSettingsDep,
    session_settings: BrowserSessionSettingsDep,
    *,
    csrf_token: str | None,
    csrf_required: bool,
) -> BrowserUserPrincipalContext | None:
    """Resolve one browser user and record its final cookie refresh."""
    session_cookie = get_session_cookie(request, session_settings)
    if session_cookie is None:
        return None
    session_data = await lifecycle_service.load_session(session_id=session_cookie)
    user = await lifecycle_service.get_user_by_id(user_id=session_data.user_id)
    if user is None or not user.is_active or not user.email_verified:
        raise BrowserSessionInvalidError
    if (
        user.sessions_invalid_before is not None
        and session_data.created_at <= user.sessions_invalid_before
    ):
        # The epoch is a defense-in-depth check for security-sensitive changes.
        raise BrowserSessionInvalidError

    if csrf_required:
        _validate_resolved_session_csrf(
            request=request,
            csrf_settings=csrf_settings,
            submitted_token=csrf_token,
            session_token=session_data.csrf,
        )
    slide_result = await lifecycle_service.slide_session(session=session_data)
    session_data = slide_result.session
    setattr(request.state, RESOLVED_BROWSER_SESSION_STATE_KEY, session_data)
    if slide_result.expiry_extended:
        cookie_max_age = remaining_session_lifetime_seconds(session_data)
        request_session_cookie_refresh(
            request,
            session_id=session_cookie,
            csrf_token=session_data.csrf,
            max_age_seconds=cookie_max_age,
        )
    return BrowserUserPrincipalContext(
        user_id=user.id,
        organization_id=user.organization_id,
        user_public_id=user.public_id,
        organization_public_id=user.organization_public_id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        organization_name=user.organization_name,
        raw_session_id=session_cookie,
        roles=frozenset(Role(role) for role in user.roles),
        authenticated_at=session_data.created_at,
    )


async def get_strict_optional_browser_user_context(
    request: Request,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    csrf_settings: CSRFSettingsDep,
    session_settings: BrowserSessionSettingsDep,
    _documented_session_cookie: BrowserSessionCookieDep = None,
) -> BrowserUserPrincipalContext | None:
    """Resolve an optional browser user while rejecting invalid credentials."""
    if get_session_cookie(request, session_settings) is None:
        return None
    csrf_header = request.headers.get(csrf_settings.header_name)
    unsafe_method = request.method.upper() in CSRF_UNSAFE_METHODS
    return await _resolve_browser_user_context(
        request=request,
        lifecycle_service=lifecycle_service,
        csrf_settings=csrf_settings,
        session_settings=session_settings,
        csrf_token=csrf_header,
        csrf_required=unsafe_method,
    )


async def resolve_optional_browser_user_context(
    *,
    request: Request,
    db_session: "AsyncSession",
    settings: "Settings",
) -> BrowserUserPrincipalContext | None:
    """Resolve a browser user without wiring session services when disabled."""
    if not settings.browser_session.enabled:
        return None
    lifecycle_service = BrowserSessionLifecycleService(
        db_session=db_session,
        settings=settings.browser_session,
    )
    return await get_strict_optional_browser_user_context(
        request=request,
        lifecycle_service=lifecycle_service,
        csrf_settings=settings.browser_session.csrf,
        session_settings=settings.browser_session,
    )


StrictOptionalBrowserUserContextDep = Annotated[
    BrowserUserPrincipalContext | None,
    Depends(get_strict_optional_browser_user_context),
]


async def get_public_optional_browser_user_context(
    request: Request,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    csrf_settings: CSRFSettingsDep,
    session_settings: BrowserSessionSettingsDep,
    _documented_session_cookie: BrowserSessionCookieDep = None,
) -> BrowserUserPrincipalContext | None:
    """Treat stale browser credentials as anonymous on public pages."""
    try:
        return await get_strict_optional_browser_user_context(
            request=request,
            lifecycle_service=lifecycle_service,
            csrf_settings=csrf_settings,
            session_settings=session_settings,
        )
    except BrowserSessionInvalidError:
        request_session_cookie_clear_always(request)
        return None


PublicOptionalBrowserUserContextDep = Annotated[
    BrowserUserPrincipalContext | None,
    Depends(get_public_optional_browser_user_context),
]


async def get_current_browser_user_context(
    optional_user_ctx: StrictOptionalBrowserUserContextDep,
) -> BrowserUserPrincipalContext:
    """Require a valid browser-session user."""
    if optional_user_ctx is not None:
        return optional_user_ctx
    raise BrowserSessionInvalidError


CurrentBrowserUserContextDep = Annotated[
    BrowserUserPrincipalContext,
    Depends(get_current_browser_user_context),
]


async def get_current_browser_form_user_context(
    request: Request,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    csrf_settings: CSRFSettingsDep,
    session_settings: BrowserSessionSettingsDep,
    _documented_session_cookie: BrowserSessionCookieDep = None,
) -> BrowserUserPrincipalContext:
    """Resolve a browser user and accept header or cached HTML-form CSRF."""
    if get_session_cookie(request, session_settings) is None:
        raise BrowserSessionInvalidError
    form = await request.form()
    form_token = form.get("csrf_token")
    if form_token is not None and not isinstance(form_token, str):
        submitted_token = None
    else:
        submitted_token = form_token or request.headers.get(csrf_settings.header_name)
    context = await _resolve_browser_user_context(
        request=request,
        lifecycle_service=lifecycle_service,
        csrf_settings=csrf_settings,
        session_settings=session_settings,
        csrf_token=submitted_token,
        csrf_required=True,
    )
    if context is None:
        raise BrowserSessionInvalidError
    return context


CurrentBrowserFormUserContextDep = Annotated[
    BrowserUserPrincipalContext,
    Depends(get_current_browser_form_user_context),
]

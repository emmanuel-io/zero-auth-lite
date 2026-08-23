"""Versioned API routes for browser-session transport."""

import secrets
from logging import getLogger
from typing import Annotated

from fastapi import APIRouter, Body, Header, Request, Response, status

from app.api.error_responses import app_error_responses
from app.api.v1.browser_sessions.schemas import LoginRequest, LogoutRequest
from app.browser_sessions.cookies import get_session_cookie
from app.browser_sessions.csrf import (
    expose_csrf_header,
    require_logout_csrf_if_session_is_valid,
    validate_double_submit_csrf,
)
from app.browser_sessions.dependencies import (
    get_resolved_browser_session,
    PublicOptionalBrowserUserContextDep,
    SessionAuthenticationServiceDep,
    SessionLifecycleServiceDep,
    SessionRevocationServiceDep,
)
from app.browser_sessions.enums import CSRFTokenExposure, LogoutScope
from app.browser_sessions.errors import (
    CSRFCookieHeaderMismatchError,
    CSRFHeaderSessionMismatchError,
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
    InvalidLoginCredentialsError,
    SessionInvalidError,
)
from app.browser_sessions.response_transport import (
    request_pre_session_csrf_cookie,
    request_session_cookie_clear_always,
    request_session_cookie_clear_on_success,
)
from app.browser_sessions.specs import SessionSpecs
from app.browser_sessions.transport import apply_login_transport
from app.core.request_ip import get_source_ip
from app.identity.public_ids import format_user_id
from app.openapi_tags import SESSION_TAG
from app.settings.dependencies import CSRFSettingsDep, SessionSettingsDep


router = APIRouter(tags=[SESSION_TAG])
logger = getLogger(__name__)


@router.post(
    "/login",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=app_error_responses(
        InvalidLoginCredentialsError,
        CSRFMissingCookieError,
        CSRFMissingHeaderError,
        CSRFCookieHeaderMismatchError,
        CSRFHeaderSessionMismatchError,
        descriptions={
            401: "Invalid email or password.",
            403: "Missing or invalid pre-session CSRF proof.",
        },
    )
    | {
        204: {"description": "Browser session created and cookies/headers updated."},
        400: {"description": "Invalid request."},
    },
)
async def login(  # noqa: PLR0913
    *,
    response: Response,
    request: Request,
    payload: LoginRequest,
    authentication_service: SessionAuthenticationServiceDep,
    csrf_settings: CSRFSettingsDep,
    session_settings: SessionSettingsDep,
    _origin: Annotated[
        str | None,
        Header(
            alias="Origin",
            description=(
                "Browser request origin. Origin or Referer is required when "
                "CSRF origin checking is enabled."
            ),
        ),
    ] = None,
    _referer: Annotated[
        str | None,
        Header(
            alias="Referer",
            description=(
                "Browser referrer used when Origin is absent and CSRF origin "
                "checking is enabled."
            ),
        ),
    ] = None,
) -> Response:
    """Authenticate a user and update browser-session transport state."""
    validate_double_submit_csrf(request=request, csrf_settings=csrf_settings)
    data = await authentication_service.login(
        email=payload.username,
        password=payload.password,
        source_ip=get_source_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    apply_login_transport(
        response,
        data,
        csrf_settings=csrf_settings,
        session_settings=session_settings,
    )
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=app_error_responses(
        SessionInvalidError,
        CSRFMissingCookieError,
        CSRFMissingHeaderError,
        CSRFCookieHeaderMismatchError,
        CSRFHeaderSessionMismatchError,
        descriptions={
            401: "The required browser session is missing or invalid.",
            403: "Missing or invalid CSRF proof for a live browser session.",
        },
    )
    | {
        204: {
            "description": "Selected browser sessions revoked; "
            "current-session cookies cleared when selected."
        }
    },
)
async def logout(  # noqa: PLR0913
    *,
    lifecycle_service: SessionLifecycleServiceDep,
    revocation_service: SessionRevocationServiceDep,
    request: Request,
    response: Response,
    csrf_settings: CSRFSettingsDep,
    session_settings: SessionSettingsDep,
    payload: Annotated[LogoutRequest, Body(default_factory=LogoutRequest)],
) -> Response:
    """Revoke the current, other, or all browser sessions for the user."""
    scope = payload.scope
    session_id = get_session_cookie(request, session_settings)
    if session_id is None:
        if scope != LogoutScope.CURRENT:
            raise SessionInvalidError
        request_session_cookie_clear_always(request)
        response.status_code = status.HTTP_204_NO_CONTENT
        return response

    session_is_valid = await require_logout_csrf_if_session_is_valid(
        request=request,
        lifecycle_service=lifecycle_service,
        csrf_settings=csrf_settings,
        session_id=session_id,
    )
    session = (
        await lifecycle_service.get_session_csrf_state(session_id=session_id)
        if session_is_valid
        else None
    )

    if scope == LogoutScope.CURRENT:
        revoked_count = int(await revocation_service.logout(session_id=session_id))
    else:
        if session is None:
            raise SessionInvalidError
        revoked_count = await revocation_service.revoke_user_sessions(
            user_id=session.user_id,
            excluded_session_id=(session_id if scope == LogoutScope.OTHERS else None),
            reason=("logout_others" if scope == LogoutScope.OTHERS else "logout_all"),
        )
    if session is not None:
        user = await lifecycle_service.get_user_by_id(user_id=session.user_id)
        logger.info(
            (
                "event=browser_session_revocation outcome=attempted subject_id=%s "
                "reason=%s revoked_sessions=%s"
            ),
            format_user_id(user.public_id) if user is not None else "unknown",
            scope.value,
            revoked_count,
        )

    if scope != LogoutScope.OTHERS:
        if session_is_valid:
            request_session_cookie_clear_on_success(request)
        else:
            request_session_cookie_clear_always(request)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get(
    "/csrf",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        204: {
            "description": (
                "Pre-session or authenticated CSRF state exposed through the "
                "configured transport."
            )
        }
    },
)
async def get_csrf_token(
    request: Request,
    user_ctx: PublicOptionalBrowserUserContextDep,
    csrf_settings: CSRFSettingsDep,
) -> Response:
    """Issue pre-session CSRF state or expose live session CSRF state."""
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.headers["Cache-Control"] = "no-store"
    if user_ctx is not None:
        session_data = get_resolved_browser_session(request)
        if session_data is None:
            msg = "Resolved browser context requires matching session state."
            raise RuntimeError(msg)
        if csrf_settings.expose_token == CSRFTokenExposure.HEADER:
            expose_csrf_header(response, session_data.csrf, csrf_settings)
        return response

    csrf_token = secrets.token_urlsafe(SessionSpecs.TOKEN_BYTES)
    request_pre_session_csrf_cookie(request, csrf_token=csrf_token)
    if csrf_settings.expose_token == CSRFTokenExposure.HEADER:
        expose_csrf_header(response, csrf_token, csrf_settings)
    return response

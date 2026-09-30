"""Server-rendered login page backed by browser-session services."""

from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, Form, Query, Request, Response, status
from starlette.responses import HTMLResponse

from app.browser_sessions.dependencies import (
    PublicOptionalBrowserUserContextDep,
)
from app.browser_sessions.errors import InvalidLoginCredentialsError
from app.browser_sessions.form_csrf import (
    get_or_create_pre_session_form_csrf,
    set_pre_session_form_csrf_cookie,
    validate_pre_session_form_csrf,
)
from app.browser_sessions.service_dependencies import (
    BrowserSessionAuthenticationServiceDep,
)
from app.browser_sessions.transport import apply_login_transport
from app.core.request_ip import get_source_ip
from app.oauth2.specs import OAuth2Specs
from app.openapi_tags import BUILTIN_AUTH_UI_TAG
from app.settings.dependencies import (
    BrowserSessionSettingsDep,
    CSRFSettingsDep,
    SettingsDep,
)
from app.settings.ui import BUILTIN_LOGIN_PATH
from app.web.auth.inputs import EmailForm, PasswordForm
from app.web.redirects import login_destination, validated_internal_return_target
from app.web.rendering import no_store_redirect, render_page
from app.web.routes import BrowserPageRoute


router = APIRouter(tags=[BUILTIN_AUTH_UI_TAG], route_class=BrowserPageRoute)


def _render_login(  # noqa: PLR0913
    request: Request,
    *,
    csrf_settings: CSRFSettingsDep,
    transaction_id: str | None = None,
    user_code: str | None = None,
    return_url: str | None = None,
    email: str = "",
    error: str | None = None,
    notice: str | None = None,
    registration_enabled: bool = False,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    """Render login with fresh anonymous CSRF state."""
    csrf_token = get_or_create_pre_session_form_csrf(request, csrf_settings)
    response = render_page(
        request,
        "auth/login.html",
        status_code=status_code,
        csrf_token=csrf_token,
        transaction_id=transaction_id,
        user_code=user_code,
        return_url=validated_internal_return_target(return_url),
        email=email,
        error=error,
        notice=notice,
        registration_enabled=registration_enabled,
    )
    set_pre_session_form_csrf_cookie(response, csrf_token, csrf_settings)
    return response


@router.get(BUILTIN_LOGIN_PATH)
async def login_page(  # noqa: PLR0913
    *,
    request: Request,
    csrf_settings: CSRFSettingsDep,
    user_ctx: PublicOptionalBrowserUserContextDep,
    settings: SettingsDep,
    transaction_id: Annotated[
        str | None,
        Query(min_length=1, max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX),
    ] = None,
    user_code: Annotated[
        str | None,
        Query(min_length=1, max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX),
    ] = None,
    return_url: Annotated[
        str | None,
        Query(min_length=1, max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX),
    ] = None,
    notice: Annotated[str | None, Query()] = None,
    error: Annotated[str | None, Query()] = None,
) -> Response:
    """Render login or continue immediately when a session already exists."""
    if user_ctx is not None:
        return no_store_redirect(
            login_destination(
                settings,
                transaction_id=transaction_id,
                user_code=user_code,
                return_url=return_url,
            ),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return _render_login(
        request,
        csrf_settings=csrf_settings,
        transaction_id=transaction_id,
        user_code=user_code,
        return_url=return_url,
        notice=notice,
        error="Invalid email or password." if error else None,
        registration_enabled=settings.identity_workflow.registration_enabled,
    )


@router.post(BUILTIN_LOGIN_PATH)
async def submit_login(  # noqa: PLR0913
    *,
    request: Request,
    authentication_service: BrowserSessionAuthenticationServiceDep,
    csrf_settings: CSRFSettingsDep,
    session_settings: BrowserSessionSettingsDep,
    settings: SettingsDep,
    email: EmailForm,
    password: PasswordForm,
    csrf_token: Annotated[str | None, Form()] = None,
    transaction_id: Annotated[
        str | None, Form(max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
    ] = None,
    user_code: Annotated[
        str | None, Form(max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
    ] = None,
    return_url: Annotated[
        str | None, Form(max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
    ] = None,
) -> Response:
    """Authenticate credentials and continue a server-owned interaction."""
    validate_pre_session_form_csrf(
        request=request,
        csrf_token=csrf_token,
        csrf_settings=csrf_settings,
    )
    try:
        data = await authentication_service.login(
            email=email,
            password=password,
            source_ip=get_source_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
    except InvalidLoginCredentialsError:
        safe_return_url = validated_internal_return_target(return_url)
        query = {"error": "invalid"}
        if transaction_id:
            query["transaction_id"] = transaction_id
        if user_code:
            query["user_code"] = user_code
        if safe_return_url:
            query["return_url"] = safe_return_url
        return no_store_redirect(
            f"{BUILTIN_LOGIN_PATH}?{urlencode(query)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    response = no_store_redirect(
        login_destination(
            settings,
            transaction_id=transaction_id,
            user_code=user_code,
            return_url=return_url,
        ),
        status_code=status.HTTP_303_SEE_OTHER,
    )
    apply_login_transport(
        response,
        data,
        csrf_settings=csrf_settings,
        session_settings=session_settings,
    )
    return response

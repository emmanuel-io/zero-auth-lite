"""Canonical authentication dependencies.

Bearer credentials and HttpOnly browser sessions converge on explicit
principal contexts before authorization is evaluated.
"""

from collections.abc import Awaitable
from logging import getLogger
from typing import Annotated, Literal, overload

from fastapi import Depends, Request, Security

from app.browser_sessions.dependencies import (
    BrowserSessionCookieDep,
    resolve_optional_browser_user_context,
)
from app.db.dependencies import DbSessionDep
from app.errors import UnauthorizedError
from app.oauth2.errors import OAuth2AccessTokenInvalidError, OAuth2SessionInvalidError
from app.oauth2.oidc.keys import get_verify_keys, OAuth2VerifyKey
from app.oauth2.principal_dependencies import OAuth2BearerPrincipalServiceDep
from app.security.dtos import (
    AuthenticatedPrincipalContext,
    OAuth2PrincipalContext,
    UserPrincipalContext,
)
from app.security.openapi import bearer, oauth2_auth_code
from app.settings.dependencies import (
    OAuth2SettingsDep,
    SettingsDep,
)


logger = getLogger(__name__)


def _oauth2_verify_keys(
    oauth2_settings: OAuth2SettingsDep,
) -> tuple[OAuth2VerifyKey, ...]:
    """Return OAuth2 verification keys from injected application settings."""
    return get_verify_keys(oauth2_settings)


def _bearer_token(
    *, bearer_creds: object | None, oauth2_creds: str | None
) -> str | None:
    """Select one bearer value from the two documented OpenAPI schemes."""
    header_token = getattr(bearer_creds, "credentials", None) if bearer_creds else None
    return header_token or oauth2_creds


async def _validate_bearer[BearerContextT](
    resolution: Awaitable[BearerContextT], *, failure_message: str
) -> BearerContextT:
    """Translate bearer validation failures into one application error contract."""
    try:
        return await resolution
    except (OAuth2AccessTokenInvalidError, OAuth2SessionInvalidError) as exc:
        logger.warning(failure_message, exc_info=exc)
        raise UnauthorizedError from exc


@overload
async def _resolve_optional_bearer(
    *,
    bearer_creds: object | None,
    oauth2_creds: str | None,
    service: OAuth2BearerPrincipalServiceDep,
    oauth2_settings: OAuth2SettingsDep,
    user_only: Literal[True],
) -> UserPrincipalContext | None: ...


@overload
async def _resolve_optional_bearer(
    *,
    bearer_creds: object | None,
    oauth2_creds: str | None,
    service: OAuth2BearerPrincipalServiceDep,
    oauth2_settings: OAuth2SettingsDep,
    user_only: Literal[False],
) -> OAuth2PrincipalContext | None: ...


async def _resolve_optional_bearer(
    *,
    bearer_creds: object | None,
    oauth2_creds: str | None,
    service: OAuth2BearerPrincipalServiceDep,
    oauth2_settings: OAuth2SettingsDep,
    user_only: bool,
) -> UserPrincipalContext | OAuth2PrincipalContext | None:
    """Resolve either documented Bearer scheme through one validation path."""
    token = _bearer_token(
        bearer_creds=bearer_creds,
        oauth2_creds=oauth2_creds,
    )
    if token is None:
        return None
    if not oauth2_settings.protocol_enabled:
        raise UnauthorizedError
    key = _oauth2_verify_keys(oauth2_settings)
    resolution = (
        service.get_current_user_context(access_token=token, key=key)
        if user_only
        else service.get_current_principal_context(access_token=token, key=key)
    )
    return await _validate_bearer(
        resolution,
        failure_message="Bearer principal validation failed",
    )


# Both Bearer schemes and the session cookie stay in the signature so OpenAPI
# describes every supported authentication transport.
async def get_optional_current_user_context(  # noqa: PLR0913
    *,
    request: Request,
    db_session: DbSessionDep,
    bearer_principal_service: OAuth2BearerPrincipalServiceDep,
    oauth2_settings: OAuth2SettingsDep,
    settings: SettingsDep,
    bearer_creds: Annotated[object | None, Security(bearer)],
    oauth2_creds: Annotated[str | None, Security(oauth2_auth_code)],
    _documented_session_cookie: BrowserSessionCookieDep = None,
) -> UserPrincipalContext | None:
    """Validate and resolve the current user from bearer token or session cookie.

    Bearer credentials take precedence. Browser-session resolution validates
    CSRF only when the request method can change state.
    """
    bearer_context = await _resolve_optional_bearer(
        bearer_creds=bearer_creds,
        oauth2_creds=oauth2_creds,
        service=bearer_principal_service,
        oauth2_settings=oauth2_settings,
        user_only=True,
    )
    if bearer_context is not None:
        return bearer_context

    if not settings.session.enabled:
        return None
    return await resolve_optional_browser_user_context(
        request=request,
        db_session=db_session,
        settings=settings,
    )


OptionalCurrentUserContextDep = Annotated[
    UserPrincipalContext | None, Depends(get_optional_current_user_context)
]


async def get_optional_current_principal_context(
    request: Request,
    bearer_principal_service: OAuth2BearerPrincipalServiceDep,
    oauth2_settings: OAuth2SettingsDep,
    bearer_creds: Annotated[object | None, Security(bearer)],
    oauth2_creds: Annotated[str | None, Security(oauth2_auth_code)],
) -> OAuth2PrincipalContext | None:
    """Validate and resolve the current OAuth2 bearer principal.

    Args:
        request (Request): The incoming request.
        bearer_principal_service: Injected OAuth2 principal service.
        oauth2_settings (OAuth2Settings): Injected OAuth2 settings.
        bearer_creds (object | None): Bearer credentials from the Authorization header.
        oauth2_creds (str | None): Bearer credentials from the OAuth2 popup.

    Returns:
        OAuth2PrincipalContext | None: Current principal, or None without a bearer.

    Raises:
        UnauthorizedError: If a bearer token is present but invalid.
    """
    _ = request
    return await _resolve_optional_bearer(
        bearer_creds=bearer_creds,
        oauth2_creds=oauth2_creds,
        service=bearer_principal_service,
        oauth2_settings=oauth2_settings,
        user_only=False,
    )


OptionalOAuth2PrincipalContextDep = Annotated[
    OAuth2PrincipalContext | None, Depends(get_optional_current_principal_context)
]


# Machine-aware routes need the same complete transport contract as user routes.
async def get_optional_current_actor_context(  # noqa: PLR0913
    *,
    request: Request,
    db_session: DbSessionDep,
    bearer_principal_service: OAuth2BearerPrincipalServiceDep,
    oauth2_settings: OAuth2SettingsDep,
    settings: SettingsDep,
    bearer_creds: Annotated[object | None, Security(bearer)],
    oauth2_creds: Annotated[str | None, Security(oauth2_auth_code)],
    _documented_session_cookie: BrowserSessionCookieDep = None,
) -> AuthenticatedPrincipalContext | None:
    """Resolve a user or client bearer before falling back to a browser session.

    This dependency is reserved for application operations that explicitly
    authorize machine clients. Ordinary identity routes should continue to use
    the user-only dependencies below.
    """
    bearer_context = await _resolve_optional_bearer(
        bearer_creds=bearer_creds,
        oauth2_creds=oauth2_creds,
        service=bearer_principal_service,
        oauth2_settings=oauth2_settings,
        user_only=False,
    )
    if bearer_context is not None:
        return bearer_context

    if not settings.session.enabled:
        return None
    return await resolve_optional_browser_user_context(
        request=request,
        db_session=db_session,
        settings=settings,
    )


OptionalCurrentActorContextDep = Annotated[
    AuthenticatedPrincipalContext | None, Depends(get_optional_current_actor_context)
]


async def get_current_actor_context(
    optional_actor_ctx: OptionalCurrentActorContextDep,
) -> AuthenticatedPrincipalContext:
    """Require a valid user or client application principal."""
    if optional_actor_ctx is not None:
        return optional_actor_ctx
    raise UnauthorizedError


CurrentActorContextDep = Annotated[
    AuthenticatedPrincipalContext, Depends(get_current_actor_context)
]


async def get_current_user_context(
    optional_user_ctx: OptionalCurrentUserContextDep,
) -> UserPrincipalContext:
    """Require a valid authenticated user context."""
    if optional_user_ctx is not None:
        return optional_user_ctx

    raise UnauthorizedError


CurrentUserContextDep = Annotated[
    UserPrincipalContext, Depends(get_current_user_context)
]


async def get_current_principal_context(
    optional_principal_ctx: OptionalOAuth2PrincipalContextDep,
) -> OAuth2PrincipalContext:
    """Dependency that ensures a valid OAuth2 bearer principal context.

    Args:
        optional_principal_ctx (OAuth2PrincipalContext | None): Resolved principal.

    Returns:
        OAuth2PrincipalContext: The resolved principal context.

    Raises:
        UnauthorizedError: If the bearer token is missing.
    """
    if optional_principal_ctx is not None:
        return optional_principal_ctx

    raise UnauthorizedError


OAuth2PrincipalContextDep = Annotated[
    OAuth2PrincipalContext, Depends(get_current_principal_context)
]

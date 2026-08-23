"""Optional OpenID Connect protocol endpoints."""

from typing import Annotated, Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    Response,
    Security,
    status,
)
from fastapi.security import HTTPAuthorizationCredentials

from app.oauth2.errors import (
    OAuth2AccessTokenInvalidError,
    OAuth2ProtocolError,
    OAuth2SessionInvalidError,
    OIDCOpenIDScopeRequiredError,
)
from app.oauth2.oidc.claims import (
    OIDC_ID_TOKEN_SIGNING_ALGS_SUPPORTED,
    OIDC_SUBJECT_TYPES_SUPPORTED,
    OIDC_SUPPORTED_CLAIMS,
    OIDC_SUPPORTED_SCOPES,
)
from app.oauth2.oidc.dependencies import OIDCUserInfoServiceDep
from app.oauth2.oidc.keys import get_verify_keys
from app.oauth2.oidc.schemas import OpenIDProviderMetadata, UserInfoResponse
from app.oauth2.principal_dependencies import OAuth2BearerPrincipalServiceDep
from app.oauth2.protocol_route import OAuth2ProtocolRoute
from app.oauth2.routers.discovery import (
    enabled_grant_types_supported,
    token_endpoint_auth_methods_supported,
)
from app.oauth2.schemas import OAuth2ErrorResponse
from app.oauth2.urls import openid_configuration_path, public_route_url
from app.openapi_tags import OIDC_TAG
from app.security.dtos import OAuth2UserPrincipalContext
from app.security.openapi import bearer
from app.settings.dependencies import SettingsDep
from app.settings.root import Settings


async def get_userinfo_principal_context(
    bearer_principal_service: OAuth2BearerPrincipalServiceDep,
    settings: SettingsDep,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Security(bearer),
    ],
) -> OAuth2UserPrincipalContext:
    """Resolve the current OAuth2 principal from a bearer access token."""
    if credentials is None:
        raise OAuth2ProtocolError(
            error="invalid_token",
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        principal = await bearer_principal_service.get_current_principal_context(
            access_token=credentials.credentials,
            key=get_verify_keys(settings.oauth2),
        )
    except (OAuth2AccessTokenInvalidError, OAuth2SessionInvalidError) as exc:
        raise OAuth2ProtocolError(
            error="invalid_token",
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    if not isinstance(principal, OAuth2UserPrincipalContext):
        raise OAuth2ProtocolError(
            error="invalid_token",
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Bearer"},
        )
    return principal


UserInfoPrincipalContextDep = Annotated[
    OAuth2UserPrincipalContext,
    Depends(get_userinfo_principal_context),
]


router = APIRouter(tags=[OIDC_TAG], route_class=OAuth2ProtocolRoute)
USERINFO_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {
        "description": "Bearer token missing or invalid.",
        "model": OAuth2ErrorResponse,
        "headers": {
            "WWW-Authenticate": {
                "schema": {"type": "string"},
                "description": "Bearer authentication challenge.",
            }
        },
    },
    403: {
        "description": "The access token lacks the openid scope.",
        "model": OAuth2ErrorResponse,
        "headers": {
            "WWW-Authenticate": {
                "schema": {"type": "string"},
                "description": "Bearer challenge with the required scope.",
            }
        },
    },
}


async def openid_configuration(
    request: Request,
    settings: SettingsDep,
) -> OpenIDProviderMetadata:
    """Return OpenID Connect discovery metadata when OIDC is enabled."""
    oauth2_settings = settings.oauth2
    if not oauth2_settings.oidc_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
    grant_types_supported = enabled_grant_types_supported(oauth2_settings)
    return OpenIDProviderMetadata(
        issuer=oauth2_settings.jwt_issuer,
        authorization_endpoint=public_route_url(
            request,
            issuer=oauth2_settings.jwt_issuer,
            route_name="authorize",
        ),
        token_endpoint=public_route_url(
            request,
            issuer=oauth2_settings.jwt_issuer,
            route_name="issue_token",
        ),
        userinfo_endpoint=public_route_url(
            request,
            issuer=oauth2_settings.jwt_issuer,
            route_name="userinfo_get",
        ),
        response_types_supported=["code"],
        grant_types_supported=grant_types_supported,
        token_endpoint_auth_methods_supported=(
            token_endpoint_auth_methods_supported(oauth2_settings)
        ),
        subject_types_supported=OIDC_SUBJECT_TYPES_SUPPORTED,
        id_token_signing_alg_values_supported=OIDC_ID_TOKEN_SIGNING_ALGS_SUPPORTED,
        scopes_supported=OIDC_SUPPORTED_SCOPES,
        claims_supported=OIDC_SUPPORTED_CLAIMS,
        code_challenge_methods_supported=["S256"],
        jwks_uri=public_route_url(
            request,
            issuer=oauth2_settings.jwt_issuer,
            route_name="jwks",
        ),
    )


def create_oidc_discovery_router(settings: Settings) -> APIRouter:
    """Create the issuer-derived OIDC discovery route."""
    discovery_router = APIRouter(tags=[OIDC_TAG], route_class=OAuth2ProtocolRoute)
    discovery_router.add_api_route(
        openid_configuration_path(settings.oauth2.jwt_issuer),
        openid_configuration,
        methods=["GET"],
        response_model=OpenIDProviderMetadata,
        response_model_exclude_none=True,
        name="openid_configuration",
    )
    return discovery_router


def _userinfo_headers(response: Response) -> None:
    """Apply cache headers for UserInfo responses."""
    response.headers["Cache-Control"] = "no-store"


async def _userinfo_response(
    *,
    response: Response,
    userinfo_service: OIDCUserInfoServiceDep,
    principal_ctx: OAuth2UserPrincipalContext,
) -> UserInfoResponse:
    """Return UserInfo while preserving Bearer error semantics."""
    _userinfo_headers(response)
    try:
        return await userinfo_service.get_userinfo(principal_ctx=principal_ctx)
    except OIDCOpenIDScopeRequiredError as exc:
        raise OAuth2ProtocolError(
            error="insufficient_scope",
            status_code=status.HTTP_403_FORBIDDEN,
            headers={"WWW-Authenticate": 'Bearer scope="openid"'},
        ) from exc
    except OAuth2SessionInvalidError as exc:
        raise OAuth2ProtocolError(
            error="invalid_token",
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


@router.get(
    "/userinfo",
    response_model_exclude_none=True,
    name="userinfo_get",
    responses=USERINFO_ERROR_RESPONSES,
)
async def userinfo_get(
    response: Response,
    userinfo_service: OIDCUserInfoServiceDep,
    principal_ctx: UserInfoPrincipalContextDep,
) -> UserInfoResponse:
    """Return OIDC userinfo claims for the bearer access token."""
    return await _userinfo_response(
        response=response,
        userinfo_service=userinfo_service,
        principal_ctx=principal_ctx,
    )


@router.post(
    "/userinfo",
    response_model_exclude_none=True,
    name="userinfo",
    responses=USERINFO_ERROR_RESPONSES,
)
async def userinfo_post(
    response: Response,
    userinfo_service: OIDCUserInfoServiceDep,
    principal_ctx: UserInfoPrincipalContextDep,
) -> UserInfoResponse:
    """Return OIDC userinfo claims for POST callers."""
    return await _userinfo_response(
        response=response,
        userinfo_service=userinfo_service,
        principal_ctx=principal_ctx,
    )

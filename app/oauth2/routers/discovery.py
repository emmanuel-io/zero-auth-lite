"""OAuth2 authorization server metadata route factory."""

from fastapi import APIRouter, Request

from app.oauth2.schemas import OAuth2AuthorizationServerMetadata
from app.oauth2.settings import OAuth2GrantType, OAuth2Settings
from app.oauth2.urls import authorization_server_metadata_path, public_route_url
from app.openapi_tags import OAUTH2_DISCOVERY_TAG
from app.settings.dependencies import OAuth2SettingsDep


def token_endpoint_auth_methods_supported(settings: OAuth2Settings) -> list[str]:
    """Return token endpoint authentication methods enabled by settings."""
    public_client_grant_enabled = any(
        settings.is_grant_enabled(grant_type)
        for grant_type in (
            OAuth2GrantType.authorization_code,
            OAuth2GrantType.refresh_token,
            OAuth2GrantType.device_code,
        )
    )
    methods = ["client_secret_basic"]
    if settings.allow_client_secret_post:
        methods.append("client_secret_post")
    if public_client_grant_enabled:
        methods.append("none")
    return methods


def enabled_grant_types_supported(settings: OAuth2Settings) -> list[str]:
    """Return enabled OAuth2 grant identifiers in deterministic order."""
    return [grant_type.value for grant_type in sorted(settings.enabled_grants())]


def _build_metadata(
    request: Request,
    settings: OAuth2SettingsDep,
) -> OAuth2AuthorizationServerMetadata:
    """Build one typed metadata response."""
    grant_types_supported = enabled_grant_types_supported(settings)
    authorization_code_enabled = settings.is_grant_enabled(
        OAuth2GrantType.authorization_code
    )
    token_endpoint_enabled = bool(grant_types_supported)
    token_endpoint_auth_methods = token_endpoint_auth_methods_supported(settings)
    return OAuth2AuthorizationServerMetadata(
        issuer=settings.jwt_issuer,
        authorization_endpoint=(
            public_route_url(
                request,
                issuer=settings.jwt_issuer,
                route_name="authorize",
            )
            if authorization_code_enabled
            else None
        ),
        token_endpoint=(
            public_route_url(
                request,
                issuer=settings.jwt_issuer,
                route_name="issue_token",
            )
            if token_endpoint_enabled
            else None
        ),
        revocation_endpoint=(
            public_route_url(
                request,
                issuer=settings.jwt_issuer,
                route_name="revoke_token",
            )
            if token_endpoint_enabled
            else None
        ),
        introspection_endpoint=(
            public_route_url(
                request,
                issuer=settings.jwt_issuer,
                route_name="introspect_token",
            )
            if token_endpoint_enabled
            else None
        ),
        response_types_supported=["code"] if authorization_code_enabled else [],
        grant_types_supported=grant_types_supported,
        token_endpoint_auth_methods_supported=(token_endpoint_auth_methods)
        if token_endpoint_enabled
        else [],
        revocation_endpoint_auth_methods_supported=(
            ["client_secret_basic", "client_secret_post", "none"]
            if settings.allow_client_secret_post
            else ["client_secret_basic", "none"]
        )
        if token_endpoint_enabled
        else [],
        introspection_endpoint_auth_methods_supported=(
            ["client_secret_basic", "client_secret_post"]
            if settings.allow_client_secret_post
            else ["client_secret_basic"]
        )
        if token_endpoint_enabled
        else [],
        code_challenge_methods_supported=(
            ["S256"] if authorization_code_enabled else []
        ),
        device_authorization_endpoint=(
            public_route_url(
                request,
                issuer=settings.jwt_issuer,
                route_name="device_authorization",
            )
            if settings.is_grant_enabled(OAuth2GrantType.device_code)
            else None
        ),
        jwks_uri=(
            public_route_url(
                request,
                issuer=settings.jwt_issuer,
                route_name="jwks",
            )
            if settings.jwks_enabled
            else None
        ),
    )


async def oauth_authorization_server_metadata(
    request: Request,
    settings: OAuth2SettingsDep,
) -> OAuth2AuthorizationServerMetadata:
    """Return OAuth2 Authorization Server Metadata."""
    return _build_metadata(request, settings)


def create_oauth_metadata_router(settings: OAuth2Settings) -> APIRouter:
    """Create the issuer-derived OAuth metadata route."""
    router = APIRouter(tags=[OAUTH2_DISCOVERY_TAG])
    router.add_api_route(
        authorization_server_metadata_path(settings.jwt_issuer),
        oauth_authorization_server_metadata,
        methods=["GET"],
        response_model=OAuth2AuthorizationServerMetadata,
        response_model_exclude_none=True,
        name="oauth_authorization_server_metadata",
    )
    return router

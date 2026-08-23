"""Tests for canonical OAuth2 route composition."""

from contextlib import suppress

import pytest
from app.oauth2.router import create_oauth2_router
from app.oauth2.settings import OAuth2Settings
from app.settings.root import Settings
from fastapi import FastAPI
from starlette.routing import NoMatchFound


pytestmark = pytest.mark.unit


def _route_paths(settings: Settings) -> set[str]:
    """Collect mounted paths from one composed OAuth2 router."""
    app = FastAPI()
    app.include_router(create_oauth2_router(settings))
    return set(app.openapi()["paths"])


def _route_names(settings: Settings) -> set[str]:
    """Collect route names from one composed OAuth2 router."""
    app = FastAPI()
    app.include_router(create_oauth2_router(settings))
    names = set()
    for name in (
        "oauth_authorization_server_metadata",
        "openid_configuration",
        "authorize",
        "issue_token",
        "device_authorization",
        "jwks",
        "userinfo",
        "userinfo_get",
    ):
        with suppress(NoMatchFound):
            app.url_path_for(name)
            names.add(name)
    return names


def test_oauth2_router_composes_enabled_protocol_and_discovery_routes() -> None:
    """Include the same OAuth2 and OIDC routes as the canonical server."""
    settings = Settings()

    assert {
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
        "/oauth2/authorize",
        "/oauth2/token",
        "/oauth2/device_authorization",
        "/oauth2/jwks.json",
        "/oauth2/userinfo",
    } <= _route_paths(settings)
    assert {
        "oauth_authorization_server_metadata",
        "openid_configuration",
        "authorize",
        "issue_token",
        "device_authorization",
        "jwks",
        "userinfo",
        "userinfo_get",
    } <= _route_names(settings)


def test_oauth2_router_is_empty_without_enabled_capabilities() -> None:
    """Omit the complete protocol surface when every capability is disabled."""
    settings = Settings(oauth2=OAuth2Settings.disabled())

    paths = _route_paths(settings)

    assert paths == set()


def test_oauth2_router_mounts_jwks_independently_of_oidc() -> None:
    """Publish verification keys without exposing OIDC identity endpoints."""
    oauth2 = OAuth2Settings().model_copy(update={"oidc_enabled": False})
    settings = Settings(oauth2=oauth2)

    paths = _route_paths(settings)

    assert "/oauth2/jwks.json" in paths
    assert "/oauth2/userinfo" not in paths
    assert "/.well-known/openid-configuration" not in paths

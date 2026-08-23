"""Smoke tests for the canonical Zero Auth Lite application wiring."""

from contextlib import suppress

import pytest
from app.browser_sessions.enums import CSRFTokenExposure
from app.browser_sessions.settings import SessionSettings
from app.main import _effective_cors_headers, create_app
from app.oauth2.settings import OAuth2Settings
from app.settings.auth import AuthSettings
from app.settings.cors import CorsSettings
from app.settings.dependencies import get_settings
from app.settings.root import Settings
from app.web.settings import (
    AuthenticationUIMode,
    OAuth2InteractionUIMode,
    UISettings,
)
from starlette.requests import Request
from starlette.routing import NoMatchFound


pytestmark = pytest.mark.unit
EXTERNAL_LOGIN_URL = "https://frontend.test/login"


def test_settings_alias_replacement_does_not_reconfigure_application() -> None:
    """Keep dependencies and lazy OpenAPI bound to the construction snapshot."""
    original = Settings()
    app = create_app(original)
    app.state.settings = Settings(oauth2=OAuth2Settings.disabled())
    request = Request({"type": "http", "app": app})

    resolved = get_settings(request)
    schema = app.openapi()

    assert resolved is original
    assert "HTTPBearer" in schema["components"]["securitySchemes"]


def _paths(settings: Settings | None = None) -> set[str]:
    app = create_app(settings)
    paths = set(app.openapi()["paths"])
    for route_name in (
        "login_page",
        "logout_page",
        "registration_page",
        "resend_verification_page",
        "forgot_password_page",
        "consent_page",
        "device_verify_page",
        "verification_page",
        "reset_password_page",
        "accept_invite_page",
    ):
        with suppress(NoMatchFound):
            paths.add(str(app.url_path_for(route_name)))
    return paths


def _sessionless_settings() -> Settings:
    """Return a machine-to-machine OAuth2 server configuration."""
    return Settings(
        session=SessionSettings(enabled=False),
        ui=UISettings(
            authentication=AuthenticationUIMode.EXTERNAL,
            oauth2_interaction=OAuth2InteractionUIMode.DISABLED,
        ),
        oauth2=OAuth2Settings().model_copy(
            update={
                "authorization_code_enabled": False,
                "device_code_enabled": False,
                "oidc_enabled": False,
            }
        ),
    )


def test_external_auth_transport_mounts_only_json_routes() -> None:
    """Expose JSON authentication without built-in authentication forms."""
    paths = _paths(
        Settings(
            ui=UISettings(
                authentication=AuthenticationUIMode.EXTERNAL,
                external_login_url=EXTERNAL_LOGIN_URL,
            ),
        )
    )

    assert "/api/v1/sessions/login" in paths
    assert "/session/login" not in paths
    assert "/login" not in paths
    assert "/consent" in paths
    assert "/api/v1/sessions/logout" in paths
    assert "/session/logout" not in paths
    assert "/api/v1/auth/register" in paths
    assert "/verify-email" not in paths
    assert "/reset-password" not in paths
    assert "/accept-invite" not in paths
    assert "/api/v1/me/sessions" in paths
    assert "/api/v1/me/password" in paths
    assert "/api/v1/auth/session/login" not in paths
    assert "/api/v1/auth/sessions" not in paths
    assert "/api/v1/admin/sessions" in paths
    assert "/api/v1/admin/organizations" in paths
    assert "/api/v1/admin/users" in paths
    assert "/api/v1/admin/oauth2/clients" in paths
    assert "/oauth2/authorize" in paths
    assert "/oauth2/device/verify" in paths
    assert "/oauth2/token" in paths
    assert "/.well-known/oauth-authorization-server" in paths
    assert "/.well-known/openid-configuration" in paths
    assert "/oauth2/jwks.json" in paths
    assert "/oauth2/userinfo" in paths


def test_builtin_authentication_ui_mounts_only_form_transport() -> None:
    """Expose HTML forms without interactive JSON authentication routes."""
    app = create_app(Settings())
    paths = set(app.openapi()["paths"])

    assert {
        "/login",
        "/logout",
        "/register",
        "/resend-verification",
        "/forgot-password",
        "/verify-email",
        "/reset-password",
        "/accept-invite",
        "/consent",
        "/oauth2/device/verify",
        "/api/v1/me",
        "/api/v1/organization",
        "/api/v1/admin/users",
        "/oauth2/token",
        "/.well-known/openid-configuration",
    } <= paths
    assert "/api/v1/auth/register" not in paths
    assert "/api/v1/sessions/login" not in paths
    assert "/api/v1/sessions/logout" not in paths
    assert "/api/v1/sessions/csrf" not in paths
    assert app.openapi()["paths"]["/login"]["post"]["tags"] == [
        "Built-in Authentication UI"
    ]
    assert app.openapi()["paths"]["/consent"]["get"]["tags"] == [
        "OAuth2 Authorization Code Flow"
    ]
    assert app.openapi()["paths"]["/oauth2/device/verify"]["get"]["tags"] == [
        "OAuth2 Device Flow"
    ]


def test_full_server_mounts_application_api_only_under_api_prefix() -> None:
    """Assert application-owned API routes are not mounted twice."""
    paths = _paths(Settings())

    assert "/api/v1/me" in paths
    assert "/api/v1/organization" in paths
    assert "/api/v1/organization/users" in paths
    assert "/api/v1/organization/oauth2/sessions" in paths
    assert "/v1/me" not in paths
    assert "/v1/organization/users" not in paths
    assert "/api/v1/organizations" not in paths
    assert "/api/v1/users" not in paths
    assert "/api/v1/oauth2/sessions" not in paths


def test_full_server_uses_direct_app_state() -> None:
    """Verify the app owns direct authentication state."""
    app = create_app()

    assert hasattr(app.state, "settings")
    assert hasattr(app.state, "password_hasher")
    assert not hasattr(app.state, "memory_session_store")
    assert not hasattr(app.state, "memory_token_store")
    assert not hasattr(app.state, "auth_runtime")
    assert not hasattr(app.state, "zero_auth")


def test_cors_headers_include_configured_session_csrf_transport() -> None:
    """Keep custom CSRF request and response headers usable across origins."""
    settings = Settings(
        cors=CorsSettings(
            allow_headers=("Content-Type",),
            expose_headers=("X-Request-Id",),
        ),
        session=SessionSettings(
            csrf={"header_name": "X-Zero-CSRF"},
        ),
    )

    allow_headers, expose_headers = _effective_cors_headers(settings)

    assert allow_headers == ("Content-Type", "X-Zero-CSRF")
    assert expose_headers == ("X-Request-Id", "X-Zero-CSRF")


def test_cookie_exposure_only_adds_csrf_request_header_to_cors() -> None:
    """Avoid advertising a CSRF response header when cookie exposure is active."""
    settings = Settings(
        cors=CorsSettings(
            allow_headers=("Content-Type",),
            expose_headers=("X-Request-Id",),
        ),
        session=SessionSettings(
            csrf={
                "header_name": "X-Zero-CSRF",
                "expose_token": CSRFTokenExposure.COOKIE,
            },
        ),
    )

    allow_headers, expose_headers = _effective_cors_headers(settings)

    assert allow_headers == ("Content-Type", "X-Zero-CSRF")
    assert expose_headers == ("X-Request-Id",)


def test_sessionless_oauth2_app_omits_browser_session_wiring() -> None:
    """Keep machine OAuth2 routes without browser-session infrastructure."""
    app = create_app(_sessionless_settings())
    schema = app.openapi()
    paths = set(schema["paths"])

    assert {
        "/oauth2/token",
        "/oauth2/revoke",
        "/oauth2/introspect",
        "/oauth2/jwks.json",
        "/.well-known/oauth-authorization-server",
        "/api/v1/admin/oauth2/clients",
    } <= paths
    assert "/api/v1/sessions/login" not in paths
    assert "/api/v1/me/sessions" not in paths
    assert "/api/v1/me/password" not in paths
    me_route_methods = {method.upper() for method in schema["paths"]["/api/v1/me"]}
    assert "DELETE" not in me_route_methods
    assert "/api/v1/admin/sessions" not in paths
    assert "/oauth2/authorize" not in paths
    assert "/oauth2/device_authorization" not in paths
    assert "/.well-known/openid-configuration" not in paths
    assert not hasattr(app.state, "memory_session_store")
    assert all(
        "session" not in item.cls.__name__.lower() for item in app.user_middleware
    )


def test_health_route_has_no_package_root_dependency() -> None:
    """Assert health route stays outside auth dependencies."""
    app = create_app()
    operation = app.openapi()["paths"]["/health"]["get"]

    assert "security" not in operation


def test_disabled_protocol_routes_are_not_mounted() -> None:
    """Assert disabled protocol features remove their routes."""
    paths = _paths(Settings(oauth2=OAuth2Settings.disabled()))

    assert "/oauth2/authorize" not in paths
    assert "/oauth2/token" not in paths
    assert "/api/v1/organization/oauth2/sessions" not in paths
    assert "/api/v1/organization/oauth2/sessions/{session_id}" not in paths
    assert "/api/v1/organization/oauth2/clients/{client_id}/tokens" not in paths
    assert "/api/v1/admin/oauth2/clients" not in paths


def test_builtin_ui_can_be_disabled_without_removing_identity_workflows() -> None:
    """Remove built-in HTML while keeping permanent identity APIs."""
    paths = _paths(
        Settings(
            ui=UISettings(
                authentication=AuthenticationUIMode.EXTERNAL,
                oauth2_interaction=OAuth2InteractionUIMode.DISABLED,
            ),
            oauth2=OAuth2Settings(device_code_enabled=False),
        )
    )

    assert {
        "/api/v1/auth/register",
        "/api/v1/auth/email/verify/request",
        "/api/v1/auth/email/verify/confirm",
        "/api/v1/auth/email/change/confirm",
        "/api/v1/auth/password/forgot",
        "/api/v1/auth/password/reset",
        "/api/v1/auth/invite/accept",
        "/api/v1/me",
        "/api/v1/organization/users",
        "/api/v1/organization/users/{user_id}/invitation",
        "/api/v1/organization",
        "/api/v1/admin/users",
        "/api/v1/admin/users/{user_id}/invitation",
        "/api/v1/admin/organizations",
    } <= paths
    assert "/verify-email" not in paths
    assert "/reset-password" not in paths
    assert "/accept-invite" not in paths
    assert "/login" not in paths
    assert "/consent" not in paths
    assert "/oauth2/device/verify" not in paths


def test_disabled_oauth2_ui_omits_consent_with_builtin_auth_forms() -> None:
    """Keep authentication forms while removing disabled OAuth2 presentation."""
    paths = _paths(
        Settings(
            ui=UISettings(
                oauth2_interaction=OAuth2InteractionUIMode.DISABLED,
            ),
            oauth2=OAuth2Settings(device_code_enabled=False),
        )
    )

    assert "/login" in paths
    assert "/oauth2/authorize" in paths
    assert "/consent" not in paths
    assert "/oauth2/device/verify" not in paths


def test_public_registration_flow_can_be_disabled_independently() -> None:
    """Remove signup verification without removing other identity workflows."""
    app = create_app(
        Settings(
            auth=AuthSettings(registration_enabled=False),
            ui=UISettings(
                authentication=AuthenticationUIMode.EXTERNAL,
                external_login_url=EXTERNAL_LOGIN_URL,
            ),
        )
    )
    paths = _paths(
        Settings(
            auth=AuthSettings(registration_enabled=False),
            ui=UISettings(
                authentication=AuthenticationUIMode.EXTERNAL,
                external_login_url=EXTERNAL_LOGIN_URL,
            ),
        )
    )

    assert "/api/v1/auth/register" not in paths
    assert "/api/v1/auth/register" not in app.openapi()["paths"]
    assert "/api/v1/auth/email/verify/request" not in paths
    assert "/api/v1/auth/email/verify/confirm" in paths
    assert {
        "/api/v1/auth/email/change/confirm",
        "/api/v1/auth/password/forgot",
        "/api/v1/auth/password/reset",
        "/api/v1/auth/invite/accept",
        "/api/v1/admin/users",
        "/api/v1/admin/users/{user_id}/invitation",
    } <= paths

    builtin_paths = _paths(
        Settings(
            auth=AuthSettings(registration_enabled=False),
        )
    )
    assert "/register" not in builtin_paths
    assert "/resend-verification" not in builtin_paths
    assert "/verify-email" in builtin_paths
    assert "/forgot-password" in builtin_paths
    assert "/reset-password" in builtin_paths
    assert "/accept-invite" in builtin_paths


def test_issuer_derived_routes_are_fixed_during_app_construction() -> None:
    """Assert custom issuer paths are registered from the startup snapshot."""
    oauth2 = OAuth2Settings()
    settings = Settings(
        oauth2=OAuth2Settings.model_validate(
            {
                **oauth2.model_dump(),
                "jwt_issuer": "https://issuer.example/organization",
            }
        )
    )

    paths = _paths(settings)

    assert "/.well-known/oauth-authorization-server/organization" in paths
    assert "/organization/.well-known/openid-configuration" in paths


def test_explicit_settings_take_precedence_over_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assert callers can construct an app from one explicit settings snapshot."""
    settings = Settings()
    monkeypatch.setenv("ZA_OAUTH2__AUTHORIZATION_CODE_ENABLED", "false")

    paths = _paths(settings)

    assert "/oauth2/token" in paths
    assert "/api/v1/admin/oauth2/clients" in paths


def test_environment_changes_do_not_reconfigure_an_existing_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assert application topology is fixed when the app is constructed."""
    app = create_app(Settings(oauth2=OAuth2Settings.disabled()))
    paths_before = set(app.openapi()["paths"])

    monkeypatch.setenv("ZA_OAUTH2__CLIENT_CREDENTIALS_ENABLED", "true")
    paths_after = set(app.openapi()["paths"])

    assert paths_after == paths_before
    assert "/oauth2/token" not in paths_after

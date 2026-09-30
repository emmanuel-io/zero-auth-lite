"""Black-box tests for the built-in OAuth2 browser interaction."""

import re
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from app.identity.users.specs import UserSpecs
from app.oauth2.authorization.code import create_s256_code_challenge
from app.web.routes import BrowserPageRoute, ManagementPageRoute
from fastapi import APIRouter, FastAPI, HTTPException, status

from tests.fixtures.auth import UserCredentials
from tests.fixtures.oauth2 import (
    CODE_VERIFIER,
    create_public_authorization_code_client,
)
from tests.fixtures.settings import app_settings
from tests.identifiers import deterministic_uuid


pytestmark = pytest.mark.api
TEST_ORIGIN = "http://testserver"
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; style-src 'self'; script-src 'self'; form-action 'self'; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
)


def _hidden_value(response: httpx.Response, name: str) -> str:
    """Extract one hidden form value from rendered HTML."""
    match = re.search(rf'name="{name}" value="([^"]+)"', response.text)
    assert match is not None
    return match.group(1)


def _assert_secure_html_headers(response: httpx.Response) -> None:
    """Assert the shared security policy on one server-rendered page."""
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["Referrer-Policy"] == "same-origin"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Content-Security-Policy"] == CONTENT_SECURITY_POLICY


def _authorization_params() -> dict[str, str]:
    """Return one valid Authorization Code with PKCE request."""
    return {
        "response_type": "code",
        "client_id": str(deterministic_uuid("public-client")),
        "redirect_uri": "https://client.example/callback",
        "scope": "read",
        "state": "browser-state",
        "code_challenge": create_s256_code_challenge(code_verifier=CODE_VERIFIER),
        "code_challenge_method": "S256",
    }


@pytest.mark.asyncio
@pytest.mark.negative
@app_settings(ui={"management_authentication": "builtin"})
async def test_resolved_browser_routes_keep_framework_and_internal_errors_html(
    app: FastAPI,
) -> None:
    """Use the route marker for safe full-page and HTMX error responses."""
    browser_router = APIRouter(route_class=BrowserPageRoute)
    management_router = APIRouter(route_class=ManagementPageRoute)

    @browser_router.get("/_test/browser-http-error")
    async def browser_http_error() -> None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Conflict")

    @management_router.get("/_test/management-internal-error")
    async def management_internal_error() -> None:
        error_message = "sensitive internal detail"
        raise RuntimeError(error_message)

    app.include_router(browser_router)
    app.include_router(management_router)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url=TEST_ORIGIN) as client:
        framework_error = await client.get("/_test/browser-http-error")
        internal_fragment = await client.get(
            "/_test/management-internal-error", headers={"HX-Request": "true"}
        )

    assert framework_error.status_code == status.HTTP_409_CONFLICT
    assert framework_error.headers["content-type"].startswith("text/html")
    assert "Conflict" in framework_error.text
    assert internal_fragment.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert internal_fragment.headers["content-type"].startswith("text/html")
    assert "Internal server error" in internal_fragment.text
    assert "sensitive internal detail" not in internal_fragment.text
    assert "<!doctype html>" not in internal_fragment.text


@pytest.mark.asyncio
@app_settings(ui={"management_authentication": "builtin"})
async def test_builtin_ui_serves_its_stylesheet(client: httpx.AsyncClient) -> None:
    """Keep the stylesheet URL rendered by browser pages backed by a real asset."""
    page = await client.get("/login")
    stylesheet = await client.get("/static/zero-auth-lite.css")

    assert page.status_code == status.HTTP_200_OK
    assert 'href="/static/zero-auth-lite.css"' in page.text
    assert "/static/vendor/htmx-4.0.0-beta6.min.js" not in page.text
    assert stylesheet.status_code == status.HTTP_200_OK
    assert stylesheet.headers["Content-Type"].startswith("text/css")
    assert "--content-width" in stylesheet.text
    assert ".auth-shell" in stylesheet.text
    assert ".app-menu" in stylesheet.text
    assert (
        ".app-menu:not([open]) > .app-nav--mobile { display: none; }" in stylesheet.text
    )


@pytest.mark.asyncio
@pytest.mark.system
@app_settings(
    ui={
        "identity_workflow_mode": "builtin",
        "management_authentication": "external",
        "oauth2_interaction": "disabled",
        "urls": {
            "login": "https://frontend.example/login",
            "logout": "https://frontend.example/logout",
        },
    },
    oauth2={"device_code_enabled": False},
)
async def test_builtin_workflow_uses_external_authentication_destination(
    client: httpx.AsyncClient,
) -> None:
    """Keep built-in identity forms usable without mounting the built-in login."""
    landing = await client.get("/")
    register_page = await client.get("/register")
    registration = await client.post(
        "/register",
        data={
            "email": "external-completion@example.com",
            "password": "Ext3rnalFlow!",
            "organization_name": "External Completion",
            "csrf_token": _hidden_value(register_page, "csrf_token"),
        },
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )

    assert landing.status_code == status.HTTP_200_OK
    assert 'href="https://frontend.example/login"' in landing.text
    assert (await client.get("/login")).status_code == status.HTTP_404_NOT_FOUND
    assert registration.status_code == status.HTTP_303_SEE_OTHER
    assert registration.headers["location"] == (
        "https://frontend.example/login?notice=registered"
    )


@pytest.mark.asyncio
@pytest.mark.system
@app_settings(ui={"management_authentication": "builtin"})
async def test_device_verification_login_preserves_only_the_user_code(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Carry the public user code through login without naming it device code."""
    bare_start = await client.get("/oauth2/device/verify", follow_redirects=False)
    assert bare_start.headers["location"] == "/login"

    start = await client.get(
        "/oauth2/device/verify",
        params={"user_code": "ABCD-EFGH"},
        follow_redirects=False,
    )
    assert start.headers["location"] == "/login?user_code=ABCD-EFGH"

    login_page = await client.get(start.headers["location"])
    assert _hidden_value(login_page, "user_code") == "ABCD-EFGH"
    assert 'name="device_code"' not in login_page.text

    response = await client.post(
        "/login",
        data={
            "email": verified_user_credentials.email,
            "password": verified_user_credentials.password,
            "csrf_token": _hidden_value(login_page, "csrf_token"),
            "user_code": "ABCD-EFGH",
        },
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )

    assert response.headers["location"] == (
        "https://auth.zero-auth-lite.localhost:8443/oauth2/device/verify"
        "?user_code=ABCD-EFGH"
    )


@pytest.mark.asyncio
@pytest.mark.system
@app_settings(
    ui={"management_authentication": "builtin"},
    default_redirect_url="https://application.example/dashboard?source=auth#complete",
)
async def test_browser_authorization_login_consent_and_callback(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Complete authorization through built-in login and consent forms."""
    await create_public_authorization_code_client(app)

    start = await client.get(
        "/oauth2/authorize",
        params=_authorization_params(),
        follow_redirects=False,
    )
    assert start.status_code == status.HTTP_303_SEE_OTHER
    assert urlparse(start.headers["location"]).path == "/login"
    transaction_id = parse_qs(urlparse(start.headers["location"]).query)[
        "transaction_id"
    ][0]

    login_page = await client.get(start.headers["location"])
    _assert_secure_html_headers(login_page)
    login_csrf = _hidden_value(login_page, "csrf_token")
    login = await client.post(
        "/login",
        data={
            "email": verified_user_credentials.email,
            "password": verified_user_credentials.password,
            "csrf_token": login_csrf,
            "transaction_id": transaction_id,
            "return_url": "/api/v1/me",
        },
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )
    assert login.status_code == status.HTTP_303_SEE_OTHER
    assert urlparse(login.headers["location"]).path == "/consent"

    consent_page = await client.get(login.headers["location"])
    assert consent_page.status_code == status.HTTP_200_OK
    _assert_secure_html_headers(consent_page)
    assert "Allow Public Client?" in consent_page.text
    assert "read" in consent_page.text
    assert "redirect_uri" not in consent_page.text
    consent_csrf = _hidden_value(consent_page, "csrf_token")
    missing_csrf = await client.post(
        "/oauth2/authorize/decision",
        data={"transaction_id": transaction_id, "decision": "approve"},
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )
    assert missing_csrf.status_code == status.HTTP_403_FORBIDDEN
    decision = await client.post(
        "/oauth2/authorize/decision",
        data={
            "transaction_id": transaction_id,
            "decision": "approve",
            "csrf_token": consent_csrf,
            "scope": "read write admin",
            "redirect_uri": "https://evil.example/callback",
        },
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )

    assert decision.status_code == status.HTTP_302_FOUND
    callback = urlparse(decision.headers["location"])
    assert callback.scheme == "https"
    assert callback.netloc == "client.example"
    query = parse_qs(callback.query)
    assert query["code"]
    assert query["state"] == ["browser-state"]

    replay = await client.post(
        "/oauth2/authorize/decision",
        data={
            "transaction_id": transaction_id,
            "decision": "approve",
            "csrf_token": consent_csrf,
        },
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )
    assert replay.status_code == status.HTTP_400_BAD_REQUEST
    assert replay.json()["error"] == "invalid_request"


@pytest.mark.asyncio
@pytest.mark.negative
@app_settings(ui={"management_authentication": "builtin"})
async def test_login_form_rejects_missing_csrf(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Reject credential submission without anonymous form proof."""
    response = await client.post(
        "/login",
        data={
            "email": verified_user_credentials.email,
            "password": verified_user_credentials.password,
        },
        headers={"Origin": TEST_ORIGIN},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
@pytest.mark.negative
@app_settings(ui={"management_authentication": "builtin"})
async def test_login_form_reports_an_origin_mismatch_separately(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Do not misreport a rejected browser origin as a cookie-value mismatch."""
    page = await client.get("/login")
    response = await client.post(
        "/login",
        data={
            "email": verified_user_credentials.email,
            "password": verified_user_credentials.password,
            "csrf_token": _hidden_value(page, "csrf_token"),
        },
        headers={"Origin": "https://untrusted.example"},
        follow_redirects=False,
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.headers["content-type"].startswith("text/html")
    assert "CSRF form origin mismatch" in response.text


@pytest.mark.asyncio
@pytest.mark.negative
@app_settings(ui={"management_authentication": "builtin"})
async def test_login_validation_failure_is_rendered_as_html(
    client: httpx.AsyncClient,
) -> None:
    """Keep FastAPI form validation inside the browser presentation contract."""
    page = await client.get("/login")
    response = await client.post(
        "/login",
        data={
            "password": "irrelevant",
            "csrf_token": _hidden_value(page, "csrf_token"),
        },
        headers={"Origin": TEST_ORIGIN},
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert response.headers["content-type"].startswith("text/html")
    assert "Check the submitted values" in response.text


@pytest.mark.asyncio
@pytest.mark.negative
@app_settings(ui={"management_authentication": "builtin"})
async def test_login_form_rejects_an_oversized_email(
    client: httpx.AsyncClient,
) -> None:
    """Apply the canonical email bound at the browser transport boundary."""
    page = await client.get("/login")
    response = await client.post(
        "/login",
        data={
            "email": "x" * (UserSpecs.EMAIL_LENGTH_MAX + 1),
            "password": "irrelevant",
            "csrf_token": _hidden_value(page, "csrf_token"),
        },
        headers={"Origin": TEST_ORIGIN},
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert response.headers["content-type"].startswith("text/html")


@pytest.mark.asyncio
@app_settings(ui={"management_authentication": "builtin"})
async def test_login_accepts_chrome_opaque_same_origin_navigation(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Accept Chrome's opaque Origin only with same-origin navigation metadata."""
    page = await client.get("/login")
    response = await client.post(
        "/login",
        data={
            "email": verified_user_credentials.email,
            "password": verified_user_credentials.password,
            "csrf_token": _hidden_value(page, "csrf_token"),
        },
        headers={
            "Origin": "null",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
        },
        follow_redirects=False,
    )

    assert response.status_code == status.HTTP_303_SEE_OTHER


@pytest.mark.asyncio
@app_settings(
    ui={"identity_workflow_mode": "builtin", "management_authentication": "builtin"},
)
async def test_landing_and_standalone_login_use_root(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Expose a useful standalone entry point before and after login."""
    landing = await client.get("/")
    assert landing.status_code == status.HTTP_200_OK
    assert "Zero Auth Lite" in landing.text
    assert 'href="/login"' in landing.text
    assert 'href="/api/docs"' in landing.text
    assert 'class="auth-card"' in landing.text
    assert 'class="app-header"' not in landing.text

    page = await client.get("/login")
    response = await client.post(
        "/login",
        data={
            "email": verified_user_credentials.email,
            "password": verified_user_credentials.password,
            "csrf_token": _hidden_value(page, "csrf_token"),
        },
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )

    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"] == "/"
    authenticated_landing = await client.get("/", follow_redirects=False)
    authenticated_login = await client.get("/login", follow_redirects=False)
    for authenticated_response in (authenticated_landing, authenticated_login):
        assert not any(
            cookie.startswith("sessionid=")
            for cookie in authenticated_response.headers.get_list("set-cookie")
        )
    assert authenticated_landing.status_code == status.HTTP_303_SEE_OTHER
    assert authenticated_landing.headers["location"] == "/management"
    dashboard = await client.get("/management")
    assert 'href="/logout"' in dashboard.text
    assert 'class="app-nav app-nav--desktop"' in dashboard.text
    assert 'href="/management/account"' in dashboard.text
    assert 'class="app-header"' in dashboard.text
    assert "Admin User" in dashboard.text
    assert "Test Organization" in dashboard.text
    assert 'class="app-identity"' in dashboard.text
    assert '<div class="brand brand--compact">' in dashboard.text
    assert 'class="dashboard-grid"' in dashboard.text
    assert 'href="/management" aria-current="page"' in dashboard.text
    assert authenticated_login.status_code == status.HTTP_303_SEE_OTHER


@pytest.mark.asyncio
@app_settings(ui={"management_authentication": "builtin"})
async def test_logout_accepts_cached_form_csrf(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Revoke a browser session using the documented CSRF form field."""
    login_page = await client.get("/login")
    await client.post(
        "/login",
        data={
            "email": verified_user_credentials.email,
            "password": verified_user_credentials.password,
            "csrf_token": _hidden_value(login_page, "csrf_token"),
        },
        headers={"Origin": TEST_ORIGIN},
    )
    logout_page = await client.get("/logout")

    response = await client.post(
        "/logout",
        data={"csrf_token": _hidden_value(logout_page, "csrf_token")},
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )

    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"] == "/login?notice=signed-out"
    assert (await client.get("/management", follow_redirects=False)).status_code == (
        status.HTTP_303_SEE_OTHER
    )


@pytest.mark.asyncio
@app_settings(ui={"management_authentication": "builtin"})
async def test_login_form_remains_valid_after_a_second_page_load(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Keep concurrent anonymous forms bound to the same active CSRF cookie."""
    first_page = await client.get("/login")
    second_page = await client.get("/login")

    assert _hidden_value(first_page, "csrf_token") == _hidden_value(
        second_page, "csrf_token"
    )
    response = await client.post(
        "/login",
        data={
            "email": verified_user_credentials.email,
            "password": verified_user_credentials.password,
            "csrf_token": _hidden_value(first_page, "csrf_token"),
        },
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )

    assert response.status_code == status.HTTP_303_SEE_OTHER


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/", "/login"])
@app_settings(
    ui={"identity_workflow_mode": "builtin", "management_authentication": "builtin"},
)
async def test_public_pages_clear_a_stale_session_cookie(
    client: httpx.AsyncClient,
    path: str,
) -> None:
    """Let users recover from an expired or revoked browser session."""
    response = await client.get(path, headers={"Cookie": "sessionid=stale-session"})

    assert response.status_code == status.HTTP_200_OK
    assert any(
        cookie.startswith("sessionid=") and "Max-Age=0" in cookie
        for cookie in response.headers.get_list("set-cookie")
    )


@pytest.mark.asyncio
@pytest.mark.negative
@app_settings(ui={"management_authentication": "builtin"})
async def test_logout_page_clears_a_stale_session_and_returns_to_login(
    client: httpx.AsyncClient,
) -> None:
    """Treat an invalid logout-page cookie as anonymous browser state."""
    response = await client.get(
        "/logout",
        headers={"Cookie": "sessionid=stale-session"},
        follow_redirects=False,
    )

    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"] == "/login"
    assert any(
        cookie.startswith("sessionid=") and "Max-Age=0" in cookie
        for cookie in response.headers.get_list("set-cookie")
    )


@pytest.mark.asyncio
@app_settings(
    ui={
        "management_authentication": "builtin",
        "oauth2_interaction": "external",
        "urls": {
            "authorization_interaction": (
                "https://frontend.example/oauth2/interaction"
            ),
            "device_interaction": "https://frontend.example/oauth2/interaction",
        },
    },
)
async def test_external_oauth2_interaction_preserves_builtin_management_login(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Keep management login local while OAuth2 uses its external frontend."""
    await create_public_authorization_code_client(app)

    response = await client.get(
        "/oauth2/authorize",
        params=_authorization_params(),
        follow_redirects=False,
    )

    destination = urlparse(response.headers["location"])
    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert f"{destination.scheme}://{destination.netloc}{destination.path}" == (
        "https://frontend.example/oauth2/interaction"
    )
    assert parse_qs(destination.query)["transaction_id"]

    management = await client.get("/management", follow_redirects=False)
    assert management.status_code == status.HTTP_303_SEE_OTHER
    assert management.headers["location"] == "/login?return_url=%2Fmanagement"


@pytest.mark.asyncio
@app_settings(ui={"management_authentication": "builtin"})
async def test_standalone_login_accepts_only_an_internal_return_target(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Carry a validated same-origin path through the login form."""
    page = await client.get("/login", params={"return_url": "/api/v1/me?view=full"})
    response = await client.post(
        "/login",
        data={
            "email": verified_user_credentials.email,
            "password": verified_user_credentials.password,
            "csrf_token": _hidden_value(page, "csrf_token"),
            "return_url": _hidden_value(page, "return_url"),
        },
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )

    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"] == "/api/v1/me?view=full"


@pytest.mark.asyncio
@app_settings(
    ui={"identity_workflow_mode": "builtin", "management_authentication": "builtin"},
    default_redirect_url="https://application.example/dashboard?source=auth#complete",
)
async def test_standalone_login_uses_configured_default_redirect(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Use the operator-owned application URL after an independent login."""
    page = await client.get("/login")
    response = await client.post(
        "/login",
        data={
            "email": verified_user_credentials.email,
            "password": verified_user_credentials.password,
            "csrf_token": _hidden_value(page, "csrf_token"),
        },
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )

    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"] == (
        "https://application.example/dashboard?source=auth#complete"
    )


@pytest.mark.asyncio
@pytest.mark.negative
@app_settings(ui={"management_authentication": "builtin"})
async def test_independent_login_ignores_arbitrary_return_url(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Never treat submitted URLs as post-login destinations."""
    page = await client.get("/login")
    response = await client.post(
        "/login",
        data={
            "email": verified_user_credentials.email,
            "password": verified_user_credentials.password,
            "csrf_token": _hidden_value(page, "csrf_token"),
            "return_url": "https://evil.example/callback",
        },
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )

    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"] == "/"


@pytest.mark.asyncio
@pytest.mark.negative
@app_settings(ui={"management_authentication": "builtin"})
async def test_unknown_consent_interaction_is_safe(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Render a generic error without reflecting transaction state."""
    login_page = await client.get("/login")
    await client.post(
        "/login",
        data={
            "email": verified_user_credentials.email,
            "password": verified_user_credentials.password,
            "csrf_token": _hidden_value(login_page, "csrf_token"),
        },
        headers={"Origin": TEST_ORIGIN},
    )

    response = await client.get("/consent?transaction_id=unknown")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "invalid or has expired" in response.text


@pytest.mark.asyncio
@app_settings(
    ui={
        "identity_workflow_mode": "external",
        "management_authentication": "external",
        "oauth2_interaction": "disabled",
        "urls": {
            "login": "https://frontend.example/login",
            "logout": "https://frontend.example/logout",
        },
    },
    oauth2={"device_code_enabled": False},
)
async def test_disabled_ui_keeps_protocol_and_denies_required_interaction(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Omit HTML routes without removing OAuth2 protocol capabilities."""
    await create_public_authorization_code_client(app)

    assert (await client.get("/login")).status_code == status.HTTP_404_NOT_FOUND
    assert (await client.get("/consent?transaction_id=x")).status_code == (
        status.HTTP_404_NOT_FOUND
    )
    response = await client.get(
        "/oauth2/authorize",
        params=_authorization_params(),
        follow_redirects=False,
    )

    assert response.status_code == status.HTTP_302_FOUND
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["error"] == ["access_denied"]
    assert query["state"] == ["browser-state"]
    assert "/oauth2/token" in app.openapi()["paths"]

"""Black-box tests for the built-in OAuth2 browser interaction."""

import re
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from app.oauth2.authorization.code import create_s256_code_challenge
from fastapi import FastAPI, status

from tests.fixtures.auth import UserCredentials
from tests.fixtures.oauth2 import (
    CODE_VERIFIER,
    create_public_authorization_code_client,
)
from tests.fixtures.settings import app_settings


pytestmark = pytest.mark.api
TEST_ORIGIN = "http://testserver"
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; style-src 'self'; form-action 'self'; "
    "frame-ancestors 'none'; base-uri 'none'"
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
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Content-Security-Policy"] == CONTENT_SECURITY_POLICY


def _authorization_params() -> dict[str, str]:
    """Return one valid Authorization Code with PKCE request."""
    return {
        "response_type": "code",
        "client_id": "public-client",
        "redirect_uri": "https://client.example/callback",
        "scope": "read",
        "state": "browser-state",
        "code_challenge": create_s256_code_challenge(code_verifier=CODE_VERIFIER),
        "code_challenge_method": "S256",
    }


@pytest.mark.asyncio
@app_settings(ui={"authentication": "builtin"})
async def test_builtin_ui_serves_its_stylesheet(client: httpx.AsyncClient) -> None:
    """Keep the stylesheet URL rendered by browser pages backed by a real asset."""
    page = await client.get("/login")
    stylesheet = await client.get("/static/zero-auth-lite.css")

    assert page.status_code == status.HTTP_200_OK
    assert 'href="/static/zero-auth-lite.css"' in page.text
    assert stylesheet.status_code == status.HTTP_200_OK
    assert stylesheet.headers["Content-Type"].startswith("text/css")
    assert ".shell" in stylesheet.text


@pytest.mark.asyncio
@pytest.mark.system
@app_settings(
    ui={"authentication": "builtin"},
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
@app_settings(ui={"authentication": "builtin"})
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
@app_settings(ui={"authentication": "builtin"})
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
    authenticated_landing = await client.get("/")
    authenticated_login = await client.get("/login", follow_redirects=False)
    for authenticated_response in (authenticated_landing, authenticated_login):
        assert not any(
            cookie.startswith("sessionid=")
            for cookie in authenticated_response.headers.get_list("set-cookie")
        )
    assert 'href="/logout"' in authenticated_landing.text
    assert authenticated_login.status_code == status.HTTP_303_SEE_OTHER


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/", "/login"])
@app_settings(ui={"authentication": "builtin"})
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
@app_settings(ui={"authentication": "builtin"})
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
        "authentication": "external",
        "external_login_url": "https://frontend.example/login",
    },
)
async def test_authorization_uses_the_external_login_destination(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Send browser authentication to the configured external frontend."""
    await create_public_authorization_code_client(app)

    response = await client.get(
        "/oauth2/authorize",
        params=_authorization_params(),
        follow_redirects=False,
    )

    destination = urlparse(response.headers["location"])
    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert f"{destination.scheme}://{destination.netloc}{destination.path}" == (
        "https://frontend.example/login"
    )
    assert parse_qs(destination.query)["transaction_id"]


@pytest.mark.asyncio
@app_settings(ui={"authentication": "builtin"})
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
    ui={"authentication": "builtin"},
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
@app_settings(
    ui={"authentication": "builtin"},
    default_redirect_url="https://application.example/dashboard?source=auth#complete",
    session={"enabled": False},
    oauth2={
        "authorization_code_enabled": False,
        "device_code_enabled": False,
        "oidc_enabled": False,
    },
)
async def test_sessionless_registration_preserves_external_destination(
    client: httpx.AsyncClient,
) -> None:
    """Preserve an external destination without exporting Zero Auth Lite notices."""
    page = await client.get("/register")

    response = await client.post(
        "/register",
        data={
            "email": "sessionless-default@example.com",
            "password": "S3ssionlessPass!",
            "organization_name": "Sessionless Registration",
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
@app_settings(
    ui={"authentication": "builtin"},
    session={"enabled": False},
    oauth2={
        "authorization_code_enabled": False,
        "device_code_enabled": False,
        "oidc_enabled": False,
    },
)
async def test_sessionless_registration_uses_root_without_default_destination(
    client: httpx.AsyncClient,
) -> None:
    """Use the server root when no login or application destination exists."""
    page = await client.get("/register")
    response = await client.post(
        "/register",
        data={
            "email": "sessionless-root@example.com",
            "password": "S3ssionlessPass!",
            "organization_name": "Sessionless Registration",
            "csrf_token": _hidden_value(page, "csrf_token"),
        },
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )

    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"] == "/"


@pytest.mark.asyncio
@pytest.mark.negative
@app_settings(ui={"authentication": "builtin"})
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
@app_settings(ui={"authentication": "builtin"})
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
    ui={"authentication": "external", "oauth2_interaction": "disabled"},
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

"""Black-box tests for built-in authentication-email pages."""

import re

import httpx
import pytest
from app.auth_tokens.enums import AuthTokenPurpose
from fastapi import FastAPI, status

from tests.fixtures.settings import app_settings
from tests.routes.api.v1.auth.test_token_workflows import notification_token


pytestmark = pytest.mark.api
TEST_ORIGIN = "http://testserver"
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; style-src 'self'; form-action 'self'; "
    "frame-ancestors 'none'; base-uri 'none'"
)


def _csrf(response: httpx.Response) -> str:
    """Read the hidden CSRF value from one workflow page."""
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match is not None
    return match.group(1)


def _assert_secure_html_headers(response: httpx.Response) -> None:
    """Assert the shared security policy on one server-rendered page."""
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["Referrer-Policy"] == "same-origin"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Content-Security-Policy"] == CONTENT_SECURITY_POLICY


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    ["/verify-email", "/reset-password", "/accept-invite"],
)
@app_settings(ui={"authentication": "builtin"})
async def test_workflow_token_pages_send_secure_html_headers(
    client: httpx.AsyncClient,
    path: str,
) -> None:
    """Prevent workflow-token URLs from propagating through browser referrers."""
    response = await client.get(path, params={"token": "workflow-token-value"})

    assert response.status_code == status.HTTP_200_OK
    _assert_secure_html_headers(response)


@pytest.mark.asyncio
@pytest.mark.system
@app_settings(ui={"authentication": "builtin"})
async def test_verification_page_requires_csrf_and_consumes_token(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Verify an email through the server-rendered adapter."""
    register_page = await client.get("/register")
    await client.post(
        "/register",
        data={
            "email": "web-verify@example.com",
            "password": "V3rifyWeb1!",
            "organization_name": "Web Verification",
            "csrf_token": _csrf(register_page),
        },
        headers={"Origin": TEST_ORIGIN},
    )
    token = await notification_token(app, AuthTokenPurpose.verify_email)
    page = await client.get("/verify-email", params={"token": token})

    missing_csrf = await client.post(
        "/verify-email",
        data={"token": token},
        headers={"Origin": TEST_ORIGIN},
    )
    response = await client.post(
        "/verify-email",
        data={"token": token, "csrf_token": _csrf(page)},
        headers={"Origin": TEST_ORIGIN},
    )

    assert page.status_code == status.HTTP_200_OK
    assert missing_csrf.status_code == status.HTTP_403_FORBIDDEN
    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"] == "/login?notice=email-verified"


@pytest.mark.asyncio
@pytest.mark.system
@app_settings(ui={"authentication": "builtin"})
async def test_password_reset_page_validates_password_and_reuses_service(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Reset a credential without consuming the token on validation failure."""
    email = "web-reset@example.com"
    register_page = await client.get("/register")
    await client.post(
        "/register",
        data={
            "email": email,
            "password": "B3foreWeb1!",
            "organization_name": "Web Reset",
            "csrf_token": _csrf(register_page),
        },
        headers={"Origin": TEST_ORIGIN},
    )
    forgot_page = await client.get("/forgot-password")
    await client.post(
        "/forgot-password",
        data={"email": email, "csrf_token": _csrf(forgot_page)},
        headers={"Origin": TEST_ORIGIN},
    )
    token = await notification_token(app, AuthTokenPurpose.reset_password)
    page = await client.get("/reset-password", params={"token": token})
    csrf_token = _csrf(page)

    weak_post = await client.post(
        "/reset-password",
        data={"token": token, "password": "weak", "csrf_token": csrf_token},
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )
    weak = await client.get(weak_post.headers["location"])
    response = await client.post(
        "/reset-password",
        data={
            "token": token,
            "password": "Aft3rWebReset!",
            "csrf_token": _csrf(weak),
        },
        headers={"Origin": TEST_ORIGIN},
    )
    login_page = await client.get("/login")
    login = await client.post(
        "/login",
        data={
            "email": email,
            "password": "Aft3rWebReset!",
            "csrf_token": _csrf(login_page),
        },
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )

    assert weak_post.status_code == status.HTTP_303_SEE_OTHER
    assert weak.status_code == status.HTTP_200_OK
    assert "meets all requirements" in weak.text
    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"] == "/login?notice=password-reset"
    assert login.status_code == status.HTTP_303_SEE_OTHER

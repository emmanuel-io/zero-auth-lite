"""Black-box tests for built-in authentication-email pages."""

import re

import httpx
import pytest
from app.workflow_tokens.enums import WorkflowTokenPurpose
from app.workflow_tokens.specs import WorkflowTokenSpecs
from fastapi import FastAPI, status

from tests.fixtures.settings import app_settings
from tests.fixtures.workflow_tokens import notification_token


pytestmark = pytest.mark.api
TEST_ORIGIN = "http://testserver"
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; style-src 'self'; script-src 'self'; form-action 'self'; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
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
@pytest.mark.negative
@app_settings(ui={"identity_workflow_mode": "builtin"})
async def test_workflow_pages_reject_oversized_tokens(
    client: httpx.AsyncClient,
) -> None:
    """Apply the canonical workflow-token bound to browser query parameters."""
    response = await client.get(
        "/verify-email",
        params={"token": "x" * (WorkflowTokenSpecs.RAW_TOKEN_LENGTH_MAX + 1)},
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert response.headers["content-type"].startswith("text/html")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    ["/verify-email", "/reset-password", "/accept-invite"],
)
@app_settings(
    ui={"identity_workflow_mode": "builtin", "management_authentication": "builtin"},
)
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
@app_settings(
    ui={"identity_workflow_mode": "builtin", "management_authentication": "builtin"},
)
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
    token = await notification_token(app, WorkflowTokenPurpose.VERIFY_EMAIL)
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
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["location"] == "/login?notice=email-verified"


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
async def test_completed_email_workflows_use_external_login(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Return built-in verification and reset forms to external authentication."""
    email = "external-email-workflows@example.com"
    register_page = await client.get("/register")
    await client.post(
        "/register",
        data={
            "email": email,
            "password": "B3foreExternal!",
            "organization_name": "External Email Workflows",
            "csrf_token": _csrf(register_page),
        },
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )
    verification_token = await notification_token(
        app, WorkflowTokenPurpose.VERIFY_EMAIL
    )
    verification_page = await client.get(
        "/verify-email", params={"token": verification_token}
    )
    verification = await client.post(
        "/verify-email",
        data={
            "token": verification_token,
            "csrf_token": _csrf(verification_page),
        },
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )

    forgot_page = await client.get("/forgot-password")
    await client.post(
        "/forgot-password",
        data={"email": email, "csrf_token": _csrf(forgot_page)},
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )
    reset_token = await notification_token(app, WorkflowTokenPurpose.RESET_PASSWORD)
    reset_page = await client.get("/reset-password", params={"token": reset_token})
    reset = await client.post(
        "/reset-password",
        data={
            "token": reset_token,
            "password": "Aft3rExternal!",
            "csrf_token": _csrf(reset_page),
        },
        headers={"Origin": TEST_ORIGIN},
        follow_redirects=False,
    )

    assert verification.status_code == status.HTTP_303_SEE_OTHER
    assert verification.headers["location"] == (
        "https://frontend.example/login?notice=email-verified"
    )
    assert reset.status_code == status.HTTP_303_SEE_OTHER
    assert reset.headers["location"] == (
        "https://frontend.example/login?notice=password-reset"
    )


@pytest.mark.asyncio
@pytest.mark.system
@app_settings(
    ui={"identity_workflow_mode": "builtin", "management_authentication": "builtin"},
)
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
    token = await notification_token(app, WorkflowTokenPurpose.RESET_PASSWORD)
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
    assert weak_post.headers["Cache-Control"] == "no-store"
    assert weak_post.headers["Pragma"] == "no-cache"
    assert weak.status_code == status.HTTP_200_OK
    assert "meets all requirements" in weak.text
    assert response.status_code == status.HTTP_303_SEE_OTHER
    assert response.headers["location"] == "/login?notice=password-reset"
    assert login.status_code == status.HTTP_303_SEE_OTHER

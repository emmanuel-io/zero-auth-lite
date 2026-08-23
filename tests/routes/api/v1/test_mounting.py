"""Black-box tests for feature-controlled API route composition."""

import httpx
import pytest
from fastapi import status

from tests.fixtures.settings import app_settings


pytestmark = pytest.mark.api


@pytest.mark.asyncio
@app_settings(ui={"authentication": "builtin"})
async def test_builtin_auth_transport_excludes_interactive_json_routes(
    client: httpx.AsyncClient,
) -> None:
    """Mount form authentication and omit its JSON transport alternative."""
    assert (await client.get("/login")).status_code == status.HTTP_200_OK
    assert (await client.get("/register")).status_code == status.HTTP_200_OK
    assert (await client.get("/forgot-password")).status_code == status.HTTP_200_OK
    assert (await client.get("/api/v1/sessions/csrf")).status_code == (
        status.HTTP_404_NOT_FOUND
    )
    assert (await client.post("/api/v1/auth/register")).status_code == (
        status.HTTP_404_NOT_FOUND
    )


@pytest.mark.asyncio
@app_settings(ui={"authentication": "external"})
async def test_external_auth_transport_excludes_builtin_auth_forms(
    client: httpx.AsyncClient,
) -> None:
    """Mount JSON authentication and omit server-rendered auth forms."""
    assert (await client.get("/login")).status_code == status.HTTP_404_NOT_FOUND
    assert (await client.get("/register")).status_code == status.HTTP_404_NOT_FOUND
    assert (await client.get("/forgot-password")).status_code == (
        status.HTTP_404_NOT_FOUND
    )
    assert (await client.get("/api/v1/sessions/csrf")).status_code == (
        status.HTTP_204_NO_CONTENT
    )


@pytest.mark.asyncio
@app_settings(
    ui={"authentication": "external", "oauth2_interaction": "disabled"},
    oauth2={"device_code_enabled": False},
)
async def test_auth_workflow_routes_remain_when_builtin_pages_are_disabled(
    client: httpx.AsyncClient,
) -> None:
    """Keep the permanent JSON API independent from built-in browser pages."""
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "user@example.com",
            "password": "S3cretPass1",
            "organization_name": "Disabled UI",
        },
    )

    assert response.status_code != status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
@app_settings(
    ui={"authentication": "external"},
    auth={"registration_enabled": False},
)
async def test_registration_start_routes_are_absent_when_disabled(
    client: httpx.AsyncClient,
) -> None:
    """Block new signup while retaining in-flight token confirmation."""
    registration_response = await client.post(
        "/api/v1/auth/register",
        json={"email": "user@example.com", "password": "S3cretPass1"},
    )
    invite_response = await client.post(
        "/api/v1/auth/invite/accept",
        json={"token": "invalid", "password": "S3cretPass1"},
    )
    verification_request = await client.post(
        "/api/v1/auth/email/verify/request",
        json={"email": "user@example.com"},
    )
    verification_confirm = await client.post(
        "/api/v1/auth/email/verify/confirm",
        json={"token": "invalid-token-value"},
    )
    email_change_confirm = await client.post(
        "/api/v1/auth/email/change/confirm",
        json={"token": "invalid-token-value"},
    )

    assert registration_response.status_code == status.HTTP_404_NOT_FOUND
    assert verification_request.status_code == status.HTTP_404_NOT_FOUND
    assert verification_confirm.status_code == status.HTTP_400_BAD_REQUEST
    assert email_change_confirm.status_code != status.HTTP_404_NOT_FOUND
    assert invite_response.status_code != status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
@app_settings(
    ui={"authentication": "builtin"},
    auth={"registration_enabled": False},
)
async def test_builtin_verification_confirmation_remains_when_registration_disabled(
    client: httpx.AsyncClient,
) -> None:
    """Keep issued verification links consumable after signup is disabled."""
    registration = await client.get("/register")
    verification_request = await client.get("/resend-verification")
    verification_confirmation = await client.get(
        "/verify-email", params={"token": "invalid-token-value"}
    )

    assert registration.status_code == status.HTTP_404_NOT_FOUND
    assert verification_request.status_code == status.HTTP_404_NOT_FOUND
    assert verification_confirmation.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
@app_settings(
    session={"enabled": False},
    oauth2={
        "authorization_code_enabled": False,
        "device_code_enabled": False,
        "oidc_enabled": False,
    },
)
async def test_session_administration_routes_are_absent_when_disabled(
    client: httpx.AsyncClient,
) -> None:
    """Assert disabling sessions removes user and operator session APIs."""
    account_response = await client.get("/api/v1/me/sessions")
    operator_response = await client.delete(
        "/api/v1/admin/sessions",
        params={"status": "expired"},
    )

    assert account_response.status_code == status.HTTP_404_NOT_FOUND
    assert operator_response.status_code == status.HTTP_404_NOT_FOUND

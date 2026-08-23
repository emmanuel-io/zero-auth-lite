"""Black-box HTTP tests for browser-session login."""

import httpx
import pytest
from app.db.models.browser_session import BrowserSessionDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.enums import UserEmailStatus
from fastapi import FastAPI, status
from sqlalchemy import func, select, update

from tests.fixtures.auth import (
    current_user_id_for_email,
    pre_session_csrf_headers,
    UserCredentials,
)
from tests.fixtures.settings import app_settings


pytestmark = pytest.mark.api
TEST_ORIGIN = "http://testserver"


async def login(
    client: httpx.AsyncClient,
    credentials: UserCredentials,
) -> httpx.Response:
    """Submit a browser-session login request."""
    headers = await pre_session_csrf_headers(client)
    return await client.post(
        "/api/v1/sessions/login",
        json={
            "username": credentials.email,
            "password": credentials.password,
        },
        headers=headers,
    )


@pytest.mark.asyncio
async def test_login_creates_a_persisted_session_and_exposes_csrf_state(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert a valid login updates the browser-session transport state."""
    response = await login(client, verified_user_credentials)

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert response.content == b""
    assert response.headers["Cache-Control"] == "no-store"
    assert app.state.settings.session.cookie_name in response.cookies
    assert app.state.settings.session.csrf.header_name in response.headers

    async with app.state.core_session_factory() as db_session:
        session_count = await db_session.scalar(
            select(func.count()).select_from(BrowserSessionDB)
        )

    assert session_count == 1


@pytest.mark.asyncio
@app_settings(session={"csrf": {"expose_token": "cookie"}})
async def test_login_exposes_csrf_through_a_readable_cookie(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert cookie exposure keeps authenticated CSRF state readable."""
    csrf_settings = app.state.settings.session.csrf
    csrf_response = await client.get("/api/v1/sessions/csrf")
    csrf_token = csrf_response.cookies[csrf_settings.cookie_name]

    response = await client.post(
        "/api/v1/sessions/login",
        json={
            "username": verified_user_credentials.email,
            "password": verified_user_credentials.password,
        },
        headers={
            "Origin": TEST_ORIGIN,
            csrf_settings.header_name: csrf_token,
        },
    )

    csrf_cookie_header = next(
        header
        for header in response.headers.get_list("set-cookie")
        if header.startswith(f"{csrf_settings.cookie_name}=")
    )
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert csrf_settings.header_name not in response.headers
    assert response.cookies[csrf_settings.cookie_name] != csrf_token
    assert "HttpOnly" not in csrf_cookie_header


@pytest.mark.asyncio
async def test_login_requires_a_pre_session_csrf_cookie(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert an exposed token is insufficient without its matching cookie."""
    csrf_settings = app.state.settings.session.csrf
    response = await client.post(
        "/api/v1/sessions/login",
        json={
            "username": verified_user_credentials.email,
            "password": verified_user_credentials.password,
        },
        headers={
            "Origin": TEST_ORIGIN,
            csrf_settings.header_name: "csrf-without-cookie",
        },
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["message"] == "CSRF cookie missing"


@pytest.mark.asyncio
async def test_login_requires_the_pre_session_csrf_header(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert the pre-session cookie cannot authorize login by itself."""
    await client.get("/api/v1/sessions/csrf")

    response = await client.post(
        "/api/v1/sessions/login",
        json={
            "username": verified_user_credentials.email,
            "password": verified_user_credentials.password,
        },
        headers={"Origin": TEST_ORIGIN},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["message"] == "CSRF header missing"


@pytest.mark.asyncio
async def test_login_rejects_mismatched_pre_session_csrf_state(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert the submitted CSRF header must match the pre-session cookie."""
    await client.get("/api/v1/sessions/csrf")
    response = await client.post(
        "/api/v1/sessions/login",
        json={
            "username": verified_user_credentials.email,
            "password": verified_user_credentials.password,
        },
        headers={
            "Origin": TEST_ORIGIN,
            app.state.settings.session.csrf.header_name: "different-token",
        },
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["message"] == "CSRF cookie header mismatch"


@pytest.mark.asyncio
async def test_login_rejects_an_untrusted_origin(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert matching pre-session state does not bypass origin validation."""
    csrf_response = await client.get("/api/v1/sessions/csrf")
    csrf_settings = app.state.settings.session.csrf
    response = await client.post(
        "/api/v1/sessions/login",
        json={
            "username": verified_user_credentials.email,
            "password": verified_user_credentials.password,
        },
        headers={
            "Origin": "https://untrusted.example",
            csrf_settings.header_name: csrf_response.headers[csrf_settings.header_name],
        },
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_login_rotates_pre_session_csrf_state(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert successful authentication replaces anonymous CSRF state."""
    csrf_settings = app.state.settings.session.csrf
    headers = await pre_session_csrf_headers(client)
    pre_session_token = headers[csrf_settings.header_name]

    response = await client.post(
        "/api/v1/sessions/login",
        json={
            "username": verified_user_credentials.email,
            "password": verified_user_credentials.password,
        },
        headers=headers,
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert response.headers[csrf_settings.header_name] != pre_session_token
    assert any(
        csrf_settings.cookie_name in header and "Max-Age=0" in header
        for header in response.headers.get_list("set-cookie")
    )


@pytest.mark.asyncio
async def test_login_matches_email_case_insensitively(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert login accepts a username with different letter case."""
    response = await login(
        client,
        UserCredentials(
            email=verified_user_credentials.email.upper(),
            password=verified_user_credentials.password,
        ),
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("username", "password"),
    [
        ("missing@example.com", "S3cretPass1"),
        ("admin@example.com", "wrong-password"),
    ],
)
@pytest.mark.negative
async def test_login_returns_generic_401_for_missing_user_and_wrong_password(
    app: FastAPI,
    client: httpx.AsyncClient,
    username: str,
    password: str,
) -> None:
    """Assert invalid credentials do not reveal which check failed."""
    headers = await pre_session_csrf_headers(client)
    csrf_cookie_name = app.state.settings.session.csrf.cookie_name
    pre_session_token = client.cookies[csrf_cookie_name]
    response = await client.post(
        "/api/v1/sessions/login",
        json={"username": username, "password": password},
        headers=headers,
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["message"] == "Invalid email or password"
    assert client.cookies[csrf_cookie_name] == pre_session_token


@pytest.mark.asyncio
@pytest.mark.negative
async def test_login_returns_generic_401_for_inactive_users(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert inactive accounts do not get a distinct login response."""
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(UserDB)
            .where(
                UserDB.id == current_user_id_for_email(verified_user_credentials.email)
            )
            .values(is_active=False)
        )
        await db_session.commit()

    response = await login(client, verified_user_credentials)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["message"] == "Invalid email or password"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_login_returns_generic_401_for_unverified_users(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert unverified accounts do not get a distinct login response."""
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(UserEmailDB)
            .where(
                UserEmailDB.normalized_email == verified_user_credentials.email.lower(),
                UserEmailDB.status == UserEmailStatus.CURRENT,
            )
            .values(verified_at=None)
        )
        await db_session.commit()

    response = await login(client, verified_user_credentials)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["message"] == "Invalid email or password"


@pytest.mark.asyncio
async def test_login_returns_structured_validation_errors(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Return safe field-level details for malformed login bodies."""
    headers = await pre_session_csrf_headers(client)
    response = await client.post(
        "/api/v1/sessions/login",
        json={"username": verified_user_credentials.email},
        headers=headers,
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert response.json() == {
        "code": "VALIDATION",
        "message": "Request validation failed.",
        "details": [
            {
                "location": ["body", "password"],
                "message": "Field required",
                "type": "missing",
            }
        ],
    }


@pytest.mark.asyncio
@app_settings(
    session={
        "cookie_domain": ".example.com",
        "csrf": {"cookie_domain": ".example.com"},
    },
)
async def test_login_uses_configured_cookie_attributes(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert the login response writes the configured cookie attributes."""
    csrf_settings = app.state.settings.session.csrf
    csrf_response = await client.get("/api/v1/sessions/csrf")
    csrf_token = csrf_response.headers[csrf_settings.header_name]
    response = await client.post(
        "/api/v1/sessions/login",
        json={
            "username": verified_user_credentials.email,
            "password": verified_user_credentials.password,
        },
        headers={
            "Cookie": f"{csrf_settings.cookie_name}={csrf_token}",
            "Origin": TEST_ORIGIN,
            csrf_settings.header_name: csrf_token,
        },
    )

    set_cookie_headers = response.headers.get_list("set-cookie")

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert any(
        f"{app.state.settings.session.cookie_name}=" in header
        and "Domain=.example.com" in header
        and "HttpOnly" in header
        for header in set_cookie_headers
    )

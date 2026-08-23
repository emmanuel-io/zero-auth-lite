"""Tests for browser-session-backed current-user dependencies."""

from datetime import datetime, timedelta, UTC

import httpx
import pytest
from app.browser_sessions.dependencies import CurrentBrowserUserContextDep
from app.browser_sessions.enums import CSRFPattern, CSRFTokenExposure
from app.core.time import as_utc_aware
from app.db.models.browser_session import BrowserSessionDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.enums import UserEmailStatus
from app.security.authentication import (
    CurrentUserContextDep,
    OptionalCurrentUserContextDep,
)
from fastapi import FastAPI, HTTPException, status
from sqlalchemy import select, update

from tests.fixtures.auth import issue_user_token, login_browser, UserCredentials
from tests.fixtures.settings import app_settings


pytestmark = pytest.mark.integration

TEST_ORIGIN = "http://testserver"


def add_optional_context_route(app: FastAPI) -> None:
    """Add a test route that exposes optional authentication state."""

    @app.api_route(
        "/test/session/optional-context",
        methods=["GET", "POST"],
        dependencies=[],
    )
    async def optional_context_route(
        user_ctx: OptionalCurrentUserContextDep,
    ) -> dict[str, bool]:
        """Return whether optional auth resolved a user context."""
        return {"authenticated": user_ctx is not None}


def add_required_context_route(app: FastAPI) -> None:
    """Add a test route that requires authentication."""

    @app.api_route(
        "/test/session/required-context",
        methods=["GET", "POST"],
        dependencies=[],
    )
    async def required_context_route(
        _user_ctx: CurrentUserContextDep,
    ) -> dict[str, bool]:
        """Return whether required auth resolved a user context."""
        return {"authenticated": True}


def add_failing_context_route(app: FastAPI) -> None:
    """Add a route that fails after browser-session resolution."""

    @app.get("/test/session/failing-context", dependencies=[])
    async def failing_context_route(_user_ctx: CurrentUserContextDep) -> None:
        """Force request rollback after the session enters its slide window."""
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="conflict")


def add_browser_required_context_route(app: FastAPI) -> None:
    """Add a test route that accepts browser sessions only."""

    @app.get("/test/session/browser-required-context", dependencies=[])
    async def browser_required_context_route(
        _user_ctx: CurrentBrowserUserContextDep,
    ) -> dict[str, bool]:
        """Return whether browser authentication resolved a user context."""
        return {"authenticated": True}


async def login_test_user(
    client: httpx.AsyncClient,
    credentials: UserCredentials,
) -> httpx.Response:
    """Log in the seeded test user and return the response."""
    return await login_browser(client, credentials)


async def request_user_token(
    app: FastAPI,
    client: httpx.AsyncClient,
    credentials: UserCredentials,
) -> httpx.Response:
    """Issue a user token through Authorization Code with PKCE."""
    return await issue_user_token(app, client, credentials)


async def set_session_expiry(app: FastAPI, expires_at: datetime) -> None:
    """Set the only persisted browser session expiry."""
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(update(BrowserSessionDB).values(expires_at=expires_at))
        await db_session.commit()


async def get_session_expiry(app: FastAPI) -> datetime:
    """Return the only persisted browser session expiry."""
    async with app.state.core_session_factory() as db_session:
        expires_at = await db_session.scalar(select(BrowserSessionDB.expires_at))

    assert expires_at is not None
    return as_utc_aware(expires_at)


async def get_session_revocation_reason(app: FastAPI) -> str | None:
    """Return the only persisted browser session revocation reason."""
    async with app.state.core_session_factory() as db_session:
        return await db_session.scalar(select(BrowserSessionDB.revoked_reason))


@pytest.mark.asyncio
async def test_optional_context_returns_none_without_credentials_on_safe_method(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert optional auth allows safe requests without credentials."""
    add_optional_context_route(app)

    response = await client.get("/test/session/optional-context")

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"authenticated": False}


@pytest.mark.asyncio
async def test_optional_context_returns_none_without_credentials_on_unsafe_method(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert optional auth skips CSRF checks when no session cookie exists."""
    add_optional_context_route(app)

    response = await client.post("/test/session/optional-context")

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"authenticated": False}


@pytest.mark.asyncio
@pytest.mark.negative
async def test_optional_context_requires_csrf_when_session_cookie_exists(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert unsafe session-authenticated requests still require CSRF."""
    add_optional_context_route(app)
    login_response = await login_test_user(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT

    response = await client.post("/test/session/optional-context")

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["message"] == "CSRF header missing"


@pytest.mark.asyncio
async def test_optional_context_returns_user_with_valid_session_and_csrf(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert optional auth resolves a valid session user context."""
    add_optional_context_route(app)
    login_response = await login_test_user(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT

    response = await client.post(
        "/test/session/optional-context",
        headers={
            "Origin": TEST_ORIGIN,
            app.state.settings.session.csrf.header_name: login_response.headers[
                app.state.settings.session.csrf.header_name
            ],
        },
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"authenticated": True}


@pytest.mark.asyncio
@app_settings(session={"csrf": {"public_origin": "https://admin.example"}})
async def test_optional_context_accepts_configured_public_origin(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert CSRF origin checks accept the configured public origin."""
    add_optional_context_route(app)
    login_response = await login_test_user(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT

    response = await client.post(
        "/test/session/optional-context",
        headers={
            "Origin": "https://admin.example",
            app.state.settings.session.csrf.header_name: login_response.headers[
                app.state.settings.session.csrf.header_name
            ],
        },
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"authenticated": True}


@pytest.mark.asyncio
@pytest.mark.negative
async def test_optional_context_rejects_untrusted_origin(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert CSRF origin checks reject origins outside the trust set."""
    add_optional_context_route(app)
    login_response = await login_test_user(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT

    response = await client.post(
        "/test/session/optional-context",
        headers={
            "Origin": "https://attacker.example",
            app.state.settings.session.csrf.header_name: login_response.headers[
                app.state.settings.session.csrf.header_name
            ],
        },
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["message"] == "CSRF cookie header mismatch"


@pytest.mark.asyncio
@app_settings(session={"csrf": {"header_name": "X-Zero-CSRF"}})
async def test_optional_context_uses_configured_csrf_header_name(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert session CSRF validation honors the configured header name."""
    custom_header_name = "X-Zero-CSRF"
    add_optional_context_route(app)
    login_response = await login_browser(
        client,
        verified_user_credentials,
        csrf_header_name=custom_header_name,
    )
    assert login_response.status_code == status.HTTP_204_NO_CONTENT

    response = await client.post(
        "/test/session/optional-context",
        headers={
            "Origin": TEST_ORIGIN,
            custom_header_name: login_response.headers[custom_header_name],
        },
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"authenticated": True}


@pytest.mark.asyncio
async def test_get_csrf_token_returns_current_session_token(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert authenticated clients can recover the synchronizer CSRF token."""
    login_response = await login_test_user(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT

    response = await client.get("/api/v1/sessions/csrf")

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert (
        response.headers[app.state.settings.session.csrf.header_name]
        == login_response.headers[app.state.settings.session.csrf.header_name]
    )


@pytest.mark.asyncio
@app_settings(session={"csrf": {"expose_token": CSRFTokenExposure.COOKIE}})
async def test_login_can_expose_csrf_token_as_cookie(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert login supports cookie-exposed CSRF tokens."""
    response = await login_test_user(client, verified_user_credentials)

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert response.content == b""
    assert app.state.settings.session.csrf.header_name not in response.headers
    csrf_cookie = response.cookies.get(app.state.settings.session.csrf.cookie_name)
    assert csrf_cookie
    set_cookie_headers = response.headers.get_list("set-cookie")
    csrf_cookie_header = next(
        header
        for header in set_cookie_headers
        if header.startswith(f"{app.state.settings.session.csrf.cookie_name}=")
    )
    assert "HttpOnly" not in csrf_cookie_header


@pytest.mark.asyncio
@app_settings(session={"csrf": {"pattern": CSRFPattern.DOUBLE_SUBMIT}})
async def test_double_submit_logout_accepts_matching_cookie_and_header(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert double-submit CSRF logout validates cookie/header equality."""
    login_response = await login_test_user(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    csrf = login_response.headers[app.state.settings.session.csrf.header_name]

    response = await client.post(
        "/api/v1/sessions/logout",
        headers={
            "Origin": TEST_ORIGIN,
            app.state.settings.session.csrf.header_name: csrf,
        },
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert response.content == b""


@pytest.mark.asyncio
@app_settings(session={"csrf": {"pattern": CSRFPattern.DOUBLE_SUBMIT}})
@pytest.mark.negative
async def test_double_submit_logout_rejects_missing_csrf_cookie(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert double-submit logout requires the CSRF cookie."""
    login_response = await login_test_user(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    client.cookies.delete(app.state.settings.session.csrf.cookie_name)

    response = await client.post(
        "/api/v1/sessions/logout",
        headers={
            "Origin": TEST_ORIGIN,
            app.state.settings.session.csrf.header_name: login_response.headers[
                app.state.settings.session.csrf.header_name
            ],
        },
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["message"] == "CSRF cookie missing"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_get_csrf_token_issues_pre_session_state_for_bearer_only_request(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert bearer auth does not replace anonymous pre-session CSRF state."""
    token_response = await request_user_token(app, client, verified_user_credentials)
    assert token_response.status_code == status.HTTP_200_OK
    client.cookies.clear()

    response = await client.get(
        "/api/v1/sessions/csrf",
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"},
    )

    csrf_settings = app.state.settings.session.csrf
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert (
        response.cookies[csrf_settings.cookie_name]
        == response.headers[csrf_settings.header_name]
    )


@pytest.mark.asyncio
@pytest.mark.negative
async def test_required_context_rejects_missing_credentials(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert required auth still rejects requests without credentials."""
    add_required_context_route(app)

    response = await client.get("/test/session/required-context")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == {
        "code": "UNAUTHORIZED",
        "message": "Unauthorized operation.",
        "details": [],
    }


@pytest.mark.asyncio
@pytest.mark.negative
async def test_browser_required_context_uses_session_error_contract(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Use one structured challenge when a browser session is absent."""
    add_browser_required_context_route(app)

    response = await client.get("/test/session/browser-required-context")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == {
        "code": "INVALID_SESSION",
        "message": "Invalid session",
        "details": [],
    }
    assert response.headers["www-authenticate"] == "Session"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_required_context_rejects_expired_session(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert expired browser sessions are rejected."""
    add_required_context_route(app)
    login_response = await login_test_user(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    await set_session_expiry(app, datetime.now(UTC) - timedelta(seconds=1))

    response = await client.get("/test/session/required-context")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["message"] == "Invalid session"
    assert response.json()["code"] == "INVALID_SESSION"
    assert response.headers["www-authenticate"] == "Session"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_expired_session_precedes_csrf_failure(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Classify expired browser authority as authentication failure first."""
    add_required_context_route(app)
    login_response = await login_test_user(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    await set_session_expiry(app, datetime.now(UTC) - timedelta(seconds=1))

    response = await client.post(
        "/test/session/required-context",
        headers={
            "Origin": TEST_ORIGIN,
            app.state.settings.session.csrf.header_name: "wrong-token",
        },
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["message"] == "Invalid session"


@pytest.mark.asyncio
@app_settings(session={"ttl_seconds": 300, "slide_seconds": 120})
async def test_required_context_slides_session_near_expiry(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert authenticated requests extend sessions inside the slide window."""
    add_required_context_route(app)
    login_response = await login_test_user(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    await set_session_expiry(app, datetime.now(UTC) + timedelta(seconds=90))
    before_request = datetime.now(UTC)

    response = await client.get("/test/session/required-context")

    persisted_expires_at = await get_session_expiry(app)
    assert response.status_code == status.HTTP_200_OK
    assert persisted_expires_at >= before_request + timedelta(seconds=300)
    assert persisted_expires_at <= datetime.now(UTC) + timedelta(seconds=300)


@pytest.mark.asyncio
@app_settings(session={"ttl_seconds": 300, "slide_seconds": 120})
async def test_required_context_keeps_session_expiry_outside_slide_window(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert authenticated requests preserve sessions outside the slide window."""
    add_required_context_route(app)
    login_response = await login_test_user(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    expires_at = datetime.now(UTC) + timedelta(seconds=180)
    await set_session_expiry(app, expires_at)

    response = await client.get("/test/session/required-context")

    assert response.status_code == status.HTTP_200_OK
    assert await get_session_expiry(app) == expires_at


@pytest.mark.asyncio
@app_settings(session={"ttl_seconds": 300, "slide_seconds": 120})
async def test_required_context_caps_cookie_at_sql_session_expiry(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert authenticated cookies do not outlive SQL session authority."""
    add_required_context_route(app)
    login_response = await login_test_user(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    await set_session_expiry(app, datetime.now(UTC) + timedelta(seconds=90))

    response = await client.get("/test/session/required-context")

    set_cookie_headers = response.headers.get_list("set-cookie")
    session_cookie_header = next(
        header
        for header in set_cookie_headers
        if f"{app.state.settings.session.cookie_name}=" in header
    )
    max_age = int(session_cookie_header.split("Max-Age=", 1)[1].split(";", 1)[0])
    assert response.status_code == status.HTTP_200_OK
    assert 0 < max_age <= app.state.settings.session.ttl_seconds


@pytest.mark.asyncio
@app_settings(session={"ttl_seconds": 300, "slide_seconds": 120})
async def test_failed_request_does_not_refresh_rolled_back_session(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Keep SQL expiry and browser transport aligned after request rollback."""
    add_failing_context_route(app)
    login_response = await login_test_user(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    expires_at = datetime.now(UTC) + timedelta(seconds=90)
    await set_session_expiry(app, expires_at)

    response = await client.get("/test/session/failing-context")

    assert response.status_code == status.HTTP_409_CONFLICT
    assert await get_session_expiry(app) == expires_at
    assert not any(
        header.startswith(f"{app.state.settings.session.cookie_name}=")
        for header in response.headers.get_list("set-cookie")
    )


@pytest.mark.asyncio
async def test_logout_all_revokes_current_user_sessions(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert a user can revoke all of their browser sessions."""
    add_required_context_route(app)
    login_response = await login_test_user(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT

    response = await client.post(
        "/api/v1/sessions/logout",
        json={"scope": "all"},
        headers={
            "Origin": TEST_ORIGIN,
            app.state.settings.session.csrf.header_name: login_response.headers[
                app.state.settings.session.csrf.header_name
            ],
        },
    )
    rejected_response = await client.get("/test/session/required-context")
    revoked_reason = await get_session_revocation_reason(app)

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert response.content == b""
    assert rejected_response.status_code == status.HTTP_401_UNAUTHORIZED
    assert revoked_reason == "logout_all"


@pytest.mark.asyncio
async def test_logout_clears_already_expired_session(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert logout succeeds and clears cookies for already expired sessions."""
    login_response = await login_test_user(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT
    await set_session_expiry(app, datetime.now(UTC) - timedelta(seconds=1))

    response = await client.post("/api/v1/sessions/logout")

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert response.cookies.get(app.state.settings.session.cookie_name) is None


@pytest.mark.asyncio
async def test_logout_without_session_cookie_still_clears_cookies(
    client: httpx.AsyncClient,
) -> None:
    """Assert logout is idempotent when no session cookie is present."""
    response = await client.post("/api/v1/sessions/logout")

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert response.content == b""


@pytest.mark.asyncio
@pytest.mark.negative
async def test_logout_rejects_missing_csrf_for_valid_session(
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert logout remains CSRF-protected while the session is valid."""
    login_response = await login_test_user(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT

    response = await client.post("/api/v1/sessions/logout")

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["message"] == "CSRF header missing"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_required_context_rejects_existing_session_for_inactive_user(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert user deactivation invalidates already issued browser sessions."""
    add_required_context_route(app)
    login_response = await login_test_user(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT

    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(UserDB)
            .where(
                UserDB.id
                == select(UserEmailDB.user_id)
                .where(
                    UserEmailDB.normalized_email
                    == verified_user_credentials.email.lower(),
                    UserEmailDB.status == UserEmailStatus.CURRENT,
                )
                .scalar_subquery()
            )
            .values(is_active=False)
        )
        await db_session.commit()

    response = await client.get("/test/session/required-context")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["message"] == "Invalid session"


@pytest.mark.asyncio
@pytest.mark.negative
async def test_required_context_rejects_existing_session_for_unverified_user(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert unverifying a user invalidates already issued browser sessions."""
    add_required_context_route(app)
    login_response = await login_test_user(client, verified_user_credentials)
    assert login_response.status_code == status.HTTP_204_NO_CONTENT

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

    response = await client.get("/test/session/required-context")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["message"] == "Invalid session"

"""Tests for service-first FastAPI browser-session helpers."""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, UTC
from http.cookies import SimpleCookie
from types import SimpleNamespace
from typing import cast, TYPE_CHECKING

import pytest
from app.browser_sessions.cookies import (
    delete_csrf_cookie,
    delete_session_cookie,
    get_session_cookie,
    set_csrf_cookie,
    set_session_cookie,
)
from app.browser_sessions.csrf import (
    expose_csrf_header,
    require_logout_csrf_if_session_is_valid,
)
from app.browser_sessions.dependencies import (
    get_current_browser_user_context,
    get_public_optional_browser_user_context,
    get_strict_optional_browser_user_context,
)
from app.browser_sessions.dtos import SessionReadDTO, SessionSlideResultDTO
from app.browser_sessions.enums import CSRFPattern, CSRFTokenExposure
from app.browser_sessions.errors import (
    CSRFCookieHeaderMismatchError,
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
    SessionInvalidError,
)
from app.browser_sessions.response_transport import (
    request_pre_session_csrf_cookie,
    request_session_cookie_clear_always,
    request_session_cookie_clear_on_success,
    request_session_cookie_refresh,
    SessionCookieMutation,
    SessionCookieMutationKind,
    SessionResponseTransportMiddleware,
)
from app.browser_sessions.settings import CSRFSettings, SessionSettings
from app.enums import Role
from app.public_ids import PublicId
from fastapi import Response, status
from starlette.requests import Request
from starlette.types import Message, Receive, Scope, Send


if TYPE_CHECKING:
    from app.browser_sessions.lifecycle import SessionLifecycleService


pytestmark = pytest.mark.unit

SESSION_COOKIE = "session-cookie"
CSRF_TOKEN = "csrf-token"  # noqa: S105
DEFAULT_USER = object()


def make_request(
    *,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> Request:
    """Build a request with optional headers and cookies."""
    raw_headers = [
        (key.lower().encode(), value.encode()) for key, value in (headers or {}).items()
    ]
    if cookies:
        cookie = SimpleCookie()
        for key, value in cookies.items():
            cookie[key] = value
        raw_headers.append(
            (b"cookie", cookie.output(header="", sep=";").strip().encode())
        )
    return Request(
        {
            "type": "http",
            "app": SimpleNamespace(state=SimpleNamespace()),
            "method": method,
            "path": "/logout",
            "headers": raw_headers,
            "scheme": "https",
            "server": ("api.test", 443),
            "query_string": b"",
        }
    )


@dataclass(slots=True)
class FakeUser:
    """Minimal user record returned by browser-session service fakes."""

    id: int = 11
    public_id: PublicId = field(default_factory=lambda: PublicId(101))
    organization_id: int = 7
    organization_public_id: PublicId = field(default_factory=lambda: PublicId(202))
    roles: frozenset[Role | str] = frozenset()
    is_active: bool = True
    email_verified: bool = True
    sessions_invalid_before: datetime | None = None


class FakeBrowserAuthService:
    """Browser-session lifecycle fake for dependency tests."""

    def __init__(
        self,
        user: FakeUser | object | None = DEFAULT_USER,
        *,
        expiry_extended: bool = True,
    ) -> None:
        """Initialize fake service state."""
        self.user = FakeUser() if user is DEFAULT_USER else user
        self.expiry_extended = expiry_extended
        self.slide_calls = 0

    async def load_session(self, *, session_id: str) -> SessionReadDTO:
        """Return a valid session DTO."""
        now = datetime.now(UTC)
        return SessionReadDTO(
            stored_session_id=session_id,
            public_id=1900000004123456,
            user_id=11,
            csrf=CSRF_TOKEN,
            absolute_expires_at=now + timedelta(hours=1),
            created_at=now,
            expires_at=now + timedelta(minutes=5),
            ip_hash=None,
            last_seen_at=now,
            revoked_at=None,
            revoked_reason=None,
            updated_at=now,
            user_agent_hash=None,
        )

    async def slide_session(self, *, session: SessionReadDTO) -> SessionSlideResultDTO:
        """Record that identity validation completed before sliding."""
        self.slide_calls += 1
        return SessionSlideResultDTO(
            session=session,
            expiry_extended=self.expiry_extended,
        )

    async def get_user_by_id(self, *, user_id: int) -> FakeUser | None:
        """Return the configured fake user."""
        _ = user_id
        return self.user


class FakeSessionService:
    """Provide a fixed CSRF token for logout helper tests."""

    async def get_session_csrf(self, *, session_id: str) -> str:
        """Return the session token or reject an expired session."""
        if session_id == "expired":
            raise SessionInvalidError
        return "csrf-token"


class InvalidatedSessionLifecycle:
    """Return a stored session older than the user's invalidation epoch."""

    def __init__(self) -> None:
        """Track whether invalid identity state reaches the sliding phase."""
        self.slide_calls = 0

    async def load_session(self, **_kwargs: object) -> SimpleNamespace:
        """Return an otherwise valid stored session."""
        return SimpleNamespace(
            user_id=1, created_at=datetime.now(UTC) - timedelta(days=1)
        )

    async def slide_session(self, **_kwargs: object) -> SimpleNamespace:
        """Fail if an invalidated user session is ever renewed."""
        self.slide_calls += 1
        msg = "invalidated sessions must not slide"
        raise AssertionError(msg)

    async def get_user_by_id(self, *, user_id: int) -> SimpleNamespace:
        """Return an active identity whose SQL epoch invalidates the session."""
        assert user_id == 1
        return SimpleNamespace(
            id=1,
            organization_id=1,
            roles=(),
            is_active=True,
            email_verified=True,
            sessions_invalid_before=datetime.now(UTC),
        )


class InvalidSessionLifecycle:
    """Reject a stale public-page session cookie."""

    async def load_session(self, **_kwargs: object) -> SessionReadDTO:
        """Reject the stored session as expired or revoked."""
        raise SessionInvalidError


@pytest.mark.asyncio
async def test_optional_browser_user_context_refreshes_double_submit_cookies() -> None:
    """Assert browser context resolves users and refreshes cookies."""
    csrf_settings = CSRFSettings(
        cookie_secure=False,
        pattern=CSRFPattern.DOUBLE_SUBMIT,
    )
    session_settings = SessionSettings(cookie_secure=False)

    request = make_request(
        headers={
            "origin": "https://api.test",
            csrf_settings.header_name: CSRF_TOKEN,
        },
        cookies={
            session_settings.cookie_name: SESSION_COOKIE,
            csrf_settings.cookie_name: CSRF_TOKEN,
        },
    )
    context = await get_strict_optional_browser_user_context(
        request=request,
        lifecycle_service=FakeBrowserAuthService(
            FakeUser(roles=frozenset({Role.ORGANIZATION_ADMIN}))
        ),  # type: ignore[arg-type]
        csrf_settings=csrf_settings,
        session_settings=session_settings,
    )

    assert context is not None
    assert context.has_administrative_role is True
    mutation = request.state.session_cookie_mutation
    assert isinstance(mutation, SessionCookieMutation)
    assert mutation.kind == SessionCookieMutationKind.REFRESH
    assert mutation.session_id == SESSION_COOKIE
    assert mutation.csrf_token == CSRF_TOKEN
    assert mutation.max_age_seconds is not None


@pytest.mark.asyncio
async def test_optional_browser_user_context_skips_cookie_without_expiry_slide() -> (
    None
):
    """Avoid Set-Cookie transport when only session activity is recorded."""
    session_settings = SessionSettings(cookie_secure=False)
    request = make_request(
        method="GET",
        cookies={session_settings.cookie_name: SESSION_COOKIE},
    )

    lifecycle_service = cast(
        "SessionLifecycleService",
        FakeBrowserAuthService(expiry_extended=False),
    )
    context = await get_strict_optional_browser_user_context(
        request=request,
        lifecycle_service=lifecycle_service,
        csrf_settings=CSRFSettings(cookie_secure=False),
        session_settings=session_settings,
    )

    assert context is not None
    assert not hasattr(request.state, "session_cookie_mutation")


@pytest.mark.asyncio
@pytest.mark.negative
async def test_optional_browser_user_context_rejects_double_submit_errors() -> None:
    """Assert double-submit browser context rejects missing and mismatched tokens."""
    csrf_settings = CSRFSettings(pattern=CSRFPattern.DOUBLE_SUBMIT)
    session_settings = SessionSettings()

    with pytest.raises(CSRFMissingHeaderError):
        await get_strict_optional_browser_user_context(
            request=make_request(
                headers={"origin": "https://api.test"},
                cookies={session_settings.cookie_name: SESSION_COOKIE},
            ),
            lifecycle_service=FakeBrowserAuthService(),  # type: ignore[arg-type]
            csrf_settings=csrf_settings,
            session_settings=session_settings,
        )

    with pytest.raises(CSRFMissingCookieError):
        await get_strict_optional_browser_user_context(
            request=make_request(
                headers={
                    "origin": "https://api.test",
                    csrf_settings.header_name: CSRF_TOKEN,
                },
                cookies={session_settings.cookie_name: SESSION_COOKIE},
            ),
            lifecycle_service=FakeBrowserAuthService(),  # type: ignore[arg-type]
            csrf_settings=csrf_settings,
            session_settings=session_settings,
        )

    with pytest.raises(CSRFCookieHeaderMismatchError):
        await get_strict_optional_browser_user_context(
            request=make_request(
                headers={"origin": "https://api.test", csrf_settings.header_name: "x"},
                cookies={
                    session_settings.cookie_name: SESSION_COOKIE,
                    csrf_settings.cookie_name: CSRF_TOKEN,
                },
            ),
            lifecycle_service=FakeBrowserAuthService(),  # type: ignore[arg-type]
            csrf_settings=csrf_settings,
            session_settings=session_settings,
        )


@pytest.mark.asyncio
@pytest.mark.negative
@pytest.mark.parametrize(
    ("user", "case"),
    [(None, "missing"), (FakeUser(is_active=False), "inactive")],
)
async def test_optional_browser_user_context_rejects_invalid_users(
    user: FakeUser | None, case: str
) -> None:
    """Assert missing and inactive users invalidate existing sessions."""
    _ = case
    session_settings = SessionSettings()

    lifecycle_service = FakeBrowserAuthService(user=user)
    with pytest.raises(SessionInvalidError):
        await get_strict_optional_browser_user_context(
            request=make_request(
                method="GET",
                cookies={session_settings.cookie_name: SESSION_COOKIE},
            ),
            lifecycle_service=lifecycle_service,  # type: ignore[arg-type]
            csrf_settings=CSRFSettings(),
            session_settings=session_settings,
        )
    assert lifecycle_service.slide_calls == 0


@pytest.mark.asyncio
async def test_sql_epoch_rejects_an_older_session() -> None:
    """The invalidation epoch remains a defense-in-depth revocation check."""
    session_settings = SessionSettings(cookie_secure=False)
    request = make_request(
        headers={
            "origin": "https://api.test",
            "x-csrf-token": "csrf-token",
        },
        cookies={session_settings.cookie_name: "older-session"},
    )

    lifecycle_service = InvalidatedSessionLifecycle()
    with pytest.raises(SessionInvalidError):
        await get_strict_optional_browser_user_context(
            request=request,
            lifecycle_service=lifecycle_service,  # type: ignore[arg-type]
            csrf_settings=CSRFSettings(cookie_secure=False),
            session_settings=session_settings,
        )
    assert lifecycle_service.slide_calls == 0


@pytest.mark.asyncio
async def test_public_optional_browser_context_clears_invalid_session() -> None:
    """Treat stale credentials as anonymous only at a public-page boundary."""
    session_settings = SessionSettings(cookie_secure=False)
    csrf_settings = CSRFSettings(cookie_secure=False)

    request = make_request(
        method="GET",
        cookies={session_settings.cookie_name: SESSION_COOKIE},
    )
    context = await get_public_optional_browser_user_context(
        request=request,
        lifecycle_service=InvalidSessionLifecycle(),  # type: ignore[arg-type]
        csrf_settings=csrf_settings,
        session_settings=session_settings,
    )

    assert context is None
    mutation = request.state.session_cookie_mutation
    assert isinstance(mutation, SessionCookieMutation)
    assert mutation.kind == SessionCookieMutationKind.CLEAR_ALWAYS


@pytest.mark.parametrize(
    "clear_kind",
    [
        SessionCookieMutationKind.CLEAR_ALWAYS,
        SessionCookieMutationKind.CLEAR_ON_SUCCESS,
    ],
)
def test_terminal_cookie_clear_cannot_be_replaced_by_a_refresh(
    clear_kind: SessionCookieMutationKind,
) -> None:
    """Keep each logout and invalid-session cleanup intent authoritative."""
    request = make_request(method="GET")

    if clear_kind == SessionCookieMutationKind.CLEAR_ALWAYS:
        request_session_cookie_clear_always(request)
    else:
        request_session_cookie_clear_on_success(request)
    request_session_cookie_refresh(
        request,
        session_id=SESSION_COOKIE,
        csrf_token=CSRF_TOKEN,
        max_age_seconds=300,
    )

    mutation = request.state.session_cookie_mutation
    assert mutation.kind == clear_kind


def test_pre_session_csrf_replaces_stale_authenticated_transport() -> None:
    """Combine stale-session cleanup with fresh anonymous CSRF state."""
    request = make_request(method="GET")

    request_session_cookie_clear_always(request)
    request_pre_session_csrf_cookie(request, csrf_token=CSRF_TOKEN)

    mutation = request.state.session_cookie_mutation
    assert mutation.kind == SessionCookieMutationKind.PRE_SESSION
    assert mutation.csrf_token == CSRF_TOKEN


def test_unconditional_clear_cannot_be_downgraded() -> None:
    """Keep error-response cleanup authoritative over transactional cleanup."""
    request = make_request(method="GET")

    request_session_cookie_clear_always(request)
    request_session_cookie_clear_on_success(request)

    mutation = request.state.session_cookie_mutation
    assert mutation.kind == SessionCookieMutationKind.CLEAR_ALWAYS


@pytest.mark.parametrize(
    "clear_request",
    [request_session_cookie_clear_always, request_session_cookie_clear_on_success],
)
def test_pre_session_transport_cannot_be_replaced_by_clear(
    clear_request: Callable[[Request], None],
) -> None:
    """Preserve newly issued anonymous CSRF state over later clear requests."""
    request = make_request(method="GET")

    request_pre_session_csrf_cookie(request, csrf_token=CSRF_TOKEN)
    clear_request(request)

    mutation = request.state.session_cookie_mutation
    assert mutation.kind == SessionCookieMutationKind.PRE_SESSION


@pytest.mark.asyncio
async def test_session_transport_replaces_conflicting_cookie_headers() -> None:
    """Emit one authoritative session cookie while preserving unrelated cookies."""

    async def endpoint(scope: Scope, receive: Receive, send: Send) -> None:
        response = Response()
        response.set_cookie("sessionid", "endpoint-value")
        response.set_cookie("unrelated", "preserved")
        await response(scope, receive, send)

    middleware = SessionResponseTransportMiddleware(
        endpoint,
        csrf_settings=CSRFSettings(cookie_secure=False),
        session_settings=SessionSettings(cookie_secure=False),
    )
    request = make_request(method="GET")
    request.scope["state"] = {}
    request.state.session_cookie_mutation = SessionCookieMutation(
        kind=SessionCookieMutationKind.REFRESH,
        session_id="authoritative-value",
        csrf_token=CSRF_TOKEN,
        max_age_seconds=300,
    )
    sent: list[Message] = []

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)

    await middleware(request.scope, receive, send)

    start = next(
        message for message in sent if message["type"] == "http.response.start"
    )
    cookie_headers = [
        value.decode()
        for name, value in start["headers"]
        if name.lower() == b"set-cookie"
    ]
    assert sum(header.startswith("sessionid=") for header in cookie_headers) == 1
    assert any(
        header.startswith("sessionid=authoritative-value") for header in cookie_headers
    )
    assert any(header.startswith("unrelated=preserved") for header in cookie_headers)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kind", "status_code", "expected_cookie_fragment"),
    [
        (
            kind,
            status_code,
            (
                None
                if success_only and status_code >= status.HTTP_400_BAD_REQUEST
                else (
                    "sessionid=session-cookie"
                    if kind == SessionCookieMutationKind.REFRESH
                    else "sessionid="
                )
            ),
        )
        for kind, success_only in (
            (SessionCookieMutationKind.REFRESH, True),
            (SessionCookieMutationKind.CLEAR_ON_SUCCESS, True),
            (SessionCookieMutationKind.CLEAR_ALWAYS, False),
            (SessionCookieMutationKind.PRE_SESSION, False),
        )
        for status_code in (204, 303, 400, 500)
    ],
)
async def test_session_transport_applies_mutations_for_response_outcome(
    kind: SessionCookieMutationKind,
    status_code: int,
    expected_cookie_fragment: str | None,
) -> None:
    """Apply each mutation according to its explicit response-outcome policy."""

    async def endpoint(scope: Scope, receive: Receive, send: Send) -> None:
        await Response(status_code=status_code)(scope, receive, send)

    middleware = SessionResponseTransportMiddleware(
        endpoint,
        csrf_settings=CSRFSettings(cookie_secure=False),
        session_settings=SessionSettings(cookie_secure=False),
    )
    request = make_request(method="GET")
    request.scope["state"] = {}
    request.state.session_cookie_mutation = SessionCookieMutation(
        kind=kind,
        session_id=SESSION_COOKIE,
        csrf_token=CSRF_TOKEN,
        max_age_seconds=300,
    )
    sent: list[Message] = []

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)

    await middleware(request.scope, receive, send)

    start = next(
        message for message in sent if message["type"] == "http.response.start"
    )
    cookie_headers = [
        value.decode()
        for name, value in start["headers"]
        if name.lower() == b"set-cookie"
    ]
    if expected_cookie_fragment is None:
        assert cookie_headers == []
    else:
        assert any(expected_cookie_fragment in header for header in cookie_headers)


def test_session_cookie_helpers_set_read_and_delete_cookie() -> None:
    """Assert session helpers preserve configured cookie attributes."""
    settings = SessionSettings(cookie_secure=False, cookie_domain=".example.test")
    response = Response()

    set_session_cookie(
        response,
        "session-value",
        settings,
        max_age_seconds=1234,
    )
    request = make_request(cookies={settings.cookie_name: "session-value"})
    delete_session_cookie(response, settings)

    assert get_session_cookie(request, settings) == "session-value"
    headers = response.headers.getlist("set-cookie")
    assert "HttpOnly" in headers[0]
    assert "Domain=.example.test" in headers[0]
    assert "Max-Age=1234" in headers[0]
    assert "Max-Age=0" in headers[1]


def test_csrf_cookie_and_header_helpers_follow_exposure_policy() -> None:
    """Assert CSRF helpers expose tokens through configured transports."""
    settings = CSRFSettings(
        cookie_secure=False,
        expose_token=CSRFTokenExposure.COOKIE,
    )
    response = Response()

    set_csrf_cookie(response, "csrf-token", settings, max_age_seconds=1234)
    expose_csrf_header(response, "csrf-token", settings)
    delete_csrf_cookie(response, settings)

    headers = response.headers.getlist("set-cookie")
    assert "HttpOnly" not in headers[0]
    assert "Max-Age=1234" in headers[0]
    assert response.headers[settings.header_name] == "csrf-token"
    assert "Max-Age=0" in headers[1]


@pytest.mark.asyncio
async def test_logout_csrf_helper_validates_live_double_submit_session() -> None:
    """Assert valid sessions require matching double-submit inputs."""
    settings = CSRFSettings(pattern=CSRFPattern.DOUBLE_SUBMIT)
    request = make_request(
        headers={"origin": "https://api.test", settings.header_name: "csrf-token"},
        cookies={settings.cookie_name: "csrf-token"},
    )

    await require_logout_csrf_if_session_is_valid(
        request=request,
        lifecycle_service=FakeSessionService(),  # type: ignore[arg-type]
        csrf_settings=settings,
        session_id="live",
    )

    with pytest.raises(CSRFMissingCookieError):
        await require_logout_csrf_if_session_is_valid(
            request=make_request(
                headers={
                    "origin": "https://api.test",
                    settings.header_name: "csrf-token",
                }
            ),
            lifecycle_service=FakeSessionService(),  # type: ignore[arg-type]
            csrf_settings=settings,
            session_id="live",
        )


@pytest.mark.asyncio
async def test_current_browser_dependency_requires_a_user() -> None:
    """Assert browser dependency escalation returns 401 explicitly."""
    with pytest.raises(SessionInvalidError) as missing:
        await get_current_browser_user_context(None)
    assert missing.value.status == status.HTTP_401_UNAUTHORIZED
    assert missing.value.headers == {"WWW-Authenticate": "Session"}

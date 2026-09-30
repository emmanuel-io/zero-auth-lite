"""Tests for authentication context dependencies."""

import logging
from http.cookies import SimpleCookie
from types import SimpleNamespace

import app.security.authentication as security_authentication
import pytest
from app.core.errors.common import UnauthorizedError
from app.oauth2.errors import OAuth2AccessTokenInvalidError
from app.oauth2.settings import OAuth2Settings
from app.security.authentication import (
    get_current_actor_context,
    get_current_user_context,
    get_optional_current_actor_context,
    get_optional_current_user_context,
)
from app.security.principals import OAuth2PrincipalContext, OAuth2UserPrincipalContext
from app.security.roles import Role
from app.settings.root import Settings
from starlette.requests import Request

from tests.identifiers import deterministic_uuid, PublicId


pytestmark = pytest.mark.unit
TEST_OAUTH2_SESSION_ID = 3
EXPECTED_INVALID_BEARER_LOG_COUNT = 2


class FakeOAuth2Service:
    """OAuth2 service fake for dependency tests."""

    def __init__(self, *, fail: bool = False) -> None:
        """Initialize fake service behavior."""
        self.fail = fail
        self.user_access_tokens: list[str] = []

    async def get_current_user_context(
        self,
        *,
        access_token: str,
        key: object,
    ) -> OAuth2UserPrincipalContext:
        """Return or reject an OAuth2 user context."""
        _ = key
        if self.fail:
            raise OAuth2AccessTokenInvalidError
        self.user_access_tokens.append(access_token)
        return OAuth2UserPrincipalContext(
            user_id=1,
            organization_id=2,
            oauth2_session_id=TEST_OAUTH2_SESSION_ID,
            client_id=deterministic_uuid("client"),
            user_public_id=PublicId(1),
            organization_public_id=PublicId(2),
            roles=frozenset({Role.ORGANIZATION_ADMIN}),
        )

    async def get_current_oauth2_principal_context(
        self,
        *,
        access_token: str,
        key: object,
    ) -> OAuth2PrincipalContext:
        """Return or reject an OAuth2 principal context."""
        _ = access_token, key
        if self.fail:
            raise OAuth2AccessTokenInvalidError
        return OAuth2UserPrincipalContext(
            organization_id=2,
            oauth2_session_id=3,
            user_id=1,
            client_id=deterministic_uuid("client"),
            user_public_id=PublicId(1),
            organization_public_id=PublicId(2),
            scopes=frozenset({"read"}),
        )


def make_request(
    *,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> Request:
    """Build a request for dependency tests."""
    raw_headers = []
    for key, value in (headers or {}).items():
        raw_headers.append((key.lower().encode(), value.encode()))
    if cookies:
        cookie = SimpleCookie()
        for key, value in cookies.items():
            cookie[key] = value
        raw_headers.append(
            (b"cookie", cookie.output(header="", sep=";").strip().encode())
        )
    app = SimpleNamespace(state=SimpleNamespace())
    return Request(
        {
            "type": "http",
            "app": app,
            "method": method,
            "path": "/unit",
            "headers": raw_headers,
            "scheme": "https",
            "server": ("api.test", 443),
            "client": ("203.0.113.10", 50000),
            "query_string": b"",
        }
    )


def bearer_credentials(token: str) -> object:
    """Return a simple bearer credentials object."""
    return SimpleNamespace(credentials=token)


@pytest.mark.asyncio
async def test_optional_current_user_context_uses_bearer_or_oauth2_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assert optional user context prefers bearer and supports OAuth2 creds."""
    monkeypatch.setattr(security_authentication, "get_verify_keys", lambda _: "key")
    request = make_request(method="GET")
    service = FakeOAuth2Service()
    first = await get_optional_current_user_context(
        request=request,
        db_session=object(),  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        bearer_principal_service=service,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        oauth2_settings=OAuth2Settings(),
        settings=Settings(),
        bearer_creds=bearer_credentials("bearer-token"),
        oauth2_creds="oauth-token",
    )
    second = await get_optional_current_user_context(
        request=request,
        db_session=object(),  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        bearer_principal_service=service,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        oauth2_settings=OAuth2Settings(),
        settings=Settings(),
        bearer_creds=None,
        oauth2_creds="oauth-token",
    )

    assert isinstance(first, OAuth2UserPrincipalContext)
    assert first.oauth2_session_id == TEST_OAUTH2_SESSION_ID
    assert isinstance(second, OAuth2UserPrincipalContext)
    assert second.oauth2_session_id == TEST_OAUTH2_SESSION_ID
    assert service.user_access_tokens == ["bearer-token", "oauth-token"]


@pytest.mark.asyncio
@pytest.mark.negative
async def test_optional_current_contexts_reject_invalid_bearer(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Normalize and log invalid bearer tokens once without a traceback."""
    monkeypatch.setattr(security_authentication, "get_verify_keys", lambda _: "key")
    caplog.set_level(logging.WARNING, logger="app.security.authentication")

    with pytest.raises(UnauthorizedError):
        await get_optional_current_user_context(
            request=make_request(method="GET"),
            db_session=object(),  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
            bearer_principal_service=FakeOAuth2Service(  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
                fail=True
            ),
            oauth2_settings=OAuth2Settings(),
            settings=Settings(),
            bearer_creds=bearer_credentials("bad"),
            oauth2_creds=None,
        )

    with pytest.raises(UnauthorizedError):
        await get_optional_current_actor_context(
            request=make_request(method="GET"),
            db_session=object(),  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
            bearer_principal_service=FakeOAuth2Service(  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
                fail=True
            ),
            oauth2_settings=OAuth2Settings(),
            settings=Settings(),
            bearer_creds=bearer_credentials("bad"),
            oauth2_creds=None,
        )

    records = [
        record
        for record in caplog.records
        if record.name == "app.security.authentication"
    ]
    assert len(records) == EXPECTED_INVALID_BEARER_LOG_COUNT
    assert all(
        record.getMessage()
        == "event=bearer_authentication outcome=failure reason=invalid_token"
        for record in records
    )
    assert all(record.exc_info is None for record in records)


@pytest.mark.asyncio
async def test_optional_current_actor_context_uses_oauth2_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assert optional principal context resolves OAuth2 popup credentials."""
    monkeypatch.setattr(security_authentication, "get_verify_keys", lambda _: "key")

    context = await get_optional_current_actor_context(
        request=make_request(method="GET"),
        db_session=object(),  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        bearer_principal_service=FakeOAuth2Service(),  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        oauth2_settings=OAuth2Settings(),
        settings=Settings(),
        bearer_creds=None,
        oauth2_creds="oauth-token",
    )

    assert context is not None
    assert isinstance(context, OAuth2UserPrincipalContext)
    assert context.user_id == 1


@pytest.mark.asyncio
async def test_required_context_dependencies_raise_when_missing() -> None:
    """Assert required context wrappers reject missing authentication."""
    with pytest.raises(UnauthorizedError) as exc_info:
        await get_current_user_context(None, Settings())

    assert exc_info.value.headers == {"WWW-Authenticate": "Bearer, Session"}

    with pytest.raises(UnauthorizedError):
        await get_current_actor_context(None, Settings())


@pytest.mark.asyncio
async def test_required_user_context_advertises_only_enabled_session_auth() -> None:
    """Do not advertise disabled Bearer authentication to API clients."""
    settings = Settings(oauth2=OAuth2Settings.disabled())

    with pytest.raises(UnauthorizedError) as exc_info:
        await get_current_user_context(None, settings)

    assert exc_info.value.headers == {"WWW-Authenticate": "Session"}

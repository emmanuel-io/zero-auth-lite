"""Tests for authentication context dependencies."""

from http.cookies import SimpleCookie
from types import SimpleNamespace

import app.security.authentication as security_authentication
import pytest
from app.enums import Role
from app.errors import UnauthorizedError
from app.oauth2.errors import OAuth2AccessTokenInvalidError
from app.oauth2.settings import OAuth2Settings
from app.security.authentication import (
    get_current_principal_context,
    get_current_user_context,
    get_optional_current_principal_context,
    get_optional_current_user_context,
)
from app.security.dtos import OAuth2PrincipalContext, OAuth2UserPrincipalContext
from app.settings.root import Settings
from starlette.requests import Request


pytestmark = pytest.mark.unit
TEST_OAUTH2_SESSION_ID = 3


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
            session_id=TEST_OAUTH2_SESSION_ID,
            client_id="client",
            roles=frozenset({Role.ORGANIZATION_ADMIN}),
        )

    async def get_current_principal_context(
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
            session_id=3,
            user_id=1,
            client_id="client",
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
        db_session=object(),  # type: ignore[arg-type]
        bearer_principal_service=service,  # type: ignore[arg-type]
        oauth2_settings=OAuth2Settings(),
        settings=Settings(),
        bearer_creds=bearer_credentials("bearer-token"),
        oauth2_creds="oauth-token",
    )
    second = await get_optional_current_user_context(
        request=request,
        db_session=object(),  # type: ignore[arg-type]
        bearer_principal_service=service,  # type: ignore[arg-type]
        oauth2_settings=OAuth2Settings(),
        settings=Settings(),
        bearer_creds=None,
        oauth2_creds="oauth-token",
    )

    assert first is not None
    assert first.session_id == TEST_OAUTH2_SESSION_ID
    assert second is not None
    assert second.session_id == TEST_OAUTH2_SESSION_ID
    assert service.user_access_tokens == ["bearer-token", "oauth-token"]


@pytest.mark.asyncio
@pytest.mark.negative
async def test_optional_current_contexts_reject_invalid_bearer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assert invalid bearer tokens are normalized to UnauthorizedError."""
    monkeypatch.setattr(security_authentication, "get_verify_keys", lambda _: "key")

    with pytest.raises(UnauthorizedError):
        await get_optional_current_user_context(
            request=make_request(method="GET"),
            db_session=object(),  # type: ignore[arg-type]
            bearer_principal_service=FakeOAuth2Service(  # type: ignore[arg-type]
                fail=True
            ),
            oauth2_settings=OAuth2Settings(),
            settings=Settings(),
            bearer_creds=bearer_credentials("bad"),
            oauth2_creds=None,
        )

    with pytest.raises(UnauthorizedError):
        await get_optional_current_principal_context(
            request=make_request(method="GET"),
            bearer_principal_service=FakeOAuth2Service(  # type: ignore[arg-type]
                fail=True
            ),
            oauth2_settings=OAuth2Settings(),
            bearer_creds=bearer_credentials("bad"),
            oauth2_creds=None,
        )


@pytest.mark.asyncio
async def test_optional_current_principal_context_uses_oauth2_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assert optional principal context resolves OAuth2 popup credentials."""
    monkeypatch.setattr(security_authentication, "get_verify_keys", lambda _: "key")

    context = await get_optional_current_principal_context(
        request=make_request(method="GET"),
        bearer_principal_service=FakeOAuth2Service(),  # type: ignore[arg-type]
        oauth2_settings=OAuth2Settings(),
        bearer_creds=None,
        oauth2_creds="oauth-token",
    )

    assert context is not None
    assert context.user_id == 1


@pytest.mark.asyncio
async def test_required_context_dependencies_raise_when_missing() -> None:
    """Assert required context wrappers reject missing authentication."""
    with pytest.raises(UnauthorizedError):
        await get_current_user_context(None)  # type: ignore[arg-type]

    with pytest.raises(UnauthorizedError):
        await get_current_principal_context(None)  # type: ignore[arg-type]

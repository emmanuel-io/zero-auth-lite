"""Tests for pure OAuth2 service helper behavior."""

from types import SimpleNamespace
from typing import cast, TYPE_CHECKING

import pytest
from app.oauth2.clients.dtos import OAuth2ClientReadDTO
from app.oauth2.settings import OAuth2GrantType, OAuth2Settings
from app.oauth2.validation import (
    normalize_scope,
    normalize_user_code,
    should_issue_refresh_token,
    user_display_name,
    validate_oidc_scope_enabled,
    validate_requested_scope,
)


pytestmark = pytest.mark.unit

if TYPE_CHECKING:
    from app.db.models.user import UserDB


def _oauth2_client(*, grant_types: list[str]) -> OAuth2ClientReadDTO:
    """Build an OAuth2 client for pure policy tests."""
    return OAuth2ClientReadDTO(
        client_id="test-client",
        client_secret=None,
        name="Test client",
        grant_types=grant_types,
        scopes=[],
        redirect_uris=None,
        is_confidential=False,
        requires_consent=False,
        is_active=True,
    )


def test_normalize_scope_deduplicates_and_preserves_order() -> None:
    """Assert repeated scopes are collapsed without sorting."""
    assert normalize_scope("read write read openid write") == "read write openid"


def test_normalize_scope_handles_empty_values() -> None:
    """Assert empty scope inputs normalize to an empty string."""
    assert normalize_scope(None) == ""
    assert normalize_scope("") == ""
    assert normalize_scope("   ") == ""


def test_validate_requested_scope_accepts_registered_scopes() -> None:
    """Assert registered scopes pass validation."""
    validate_requested_scope(
        requested_scope="read write",
        allowed_scopes=["read", "write"],
    )


@pytest.mark.negative
def test_validate_requested_scope_rejects_unregistered_scope() -> None:
    """Assert unregistered scopes are rejected with the OAuth2 error string."""
    with pytest.raises(ValueError, match="invalid_scope"):
        validate_requested_scope(
            requested_scope="read admin",
            allowed_scopes=["read"],
        )


def test_validate_oidc_scope_enabled_accepts_openid_when_enabled() -> None:
    """Assert OIDC scopes are accepted when OIDC support is enabled."""
    validate_oidc_scope_enabled(requested_scope="openid email", oidc_enabled=True)


@pytest.mark.negative
def test_validate_oidc_scope_enabled_rejects_openid_when_disabled() -> None:
    """Assert OIDC scopes are rejected when OIDC support is disabled."""
    with pytest.raises(ValueError, match="invalid_scope"):
        validate_oidc_scope_enabled(
            requested_scope="openid email",
            oidc_enabled=False,
        )


def test_validate_oidc_scope_enabled_ignores_non_oidc_scope_when_disabled() -> None:
    """Assert non-OIDC scopes remain valid while OIDC is disabled."""
    validate_oidc_scope_enabled(requested_scope="read", oidc_enabled=False)


def test_user_display_name_joins_available_profile_names() -> None:
    """Assert user display names are built from available name fields."""
    user = cast(
        "UserDB",
        SimpleNamespace(first_name="Ada", last_name="Lovelace"),
    )

    assert user_display_name(user) == "Ada Lovelace"


def test_user_display_name_returns_none_without_profile_names() -> None:
    """Assert missing profile names produce no display name claim."""
    user = cast("UserDB", SimpleNamespace(first_name="", last_name=""))

    assert user_display_name(user) is None


def test_normalize_user_code_removes_spaces_and_uppercases() -> None:
    """Assert device user codes are normalized for lookup."""
    assert normalize_user_code(" abcd ef12 ") == "ABCDEF12"


def test_refresh_token_issuance_requires_enabled_server_grant() -> None:
    """Assert disabled server configuration prevents refresh-token issuance."""
    client = _oauth2_client(grant_types=[OAuth2GrantType.refresh_token.value])

    assert not should_issue_refresh_token(
        settings=OAuth2Settings.disabled(), client=client
    )


def test_refresh_token_issuance_requires_client_grant() -> None:
    """Assert a client must be configured for refresh-token issuance."""
    settings = OAuth2Settings.disabled().model_copy(
        update={"refresh_token_enabled": True}
    )
    client = _oauth2_client(grant_types=[])

    assert not should_issue_refresh_token(settings=settings, client=client)


def test_refresh_token_issuance_accepts_enabled_client_grant() -> None:
    """Assert matching server and client grants permit refresh-token issuance."""
    settings = OAuth2Settings.disabled().model_copy(
        update={"refresh_token_enabled": True}
    )
    client = _oauth2_client(grant_types=[OAuth2GrantType.refresh_token.value])

    assert should_issue_refresh_token(settings=settings, client=client)

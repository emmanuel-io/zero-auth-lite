"""Tests for current-user API route handlers."""

import pytest
from app.api.v1.me.profile import get_me, patch_me
from app.api.v1.me.schemas import CurrentUserProfilePatchRequest
from app.security.dtos import BrowserUserPrincipalContext
from pydantic import ValidationError

from tests.fixtures.api import TEST_PASSWORD
from tests.mocks.api import FakeUserSelfService


pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_me_routes_call_user_service() -> None:
    """Assert /me route handlers return service results."""
    service = FakeUserSelfService()
    user_ctx = BrowserUserPrincipalContext(
        user_id=1, organization_id=1, session_id="session"
    )

    get_response = await get_me(
        _principal=user_ctx,
        user_service=service,  # type: ignore[arg-type]
    )
    patch_response = await patch_me(
        _principal=user_ctx,
        payload=CurrentUserProfilePatchRequest(email="patched@example.com"),
        user_service=service,  # type: ignore[arg-type]
    )
    assert get_response.organization.name == "Test Organization"
    assert str(patch_response.email) == "patched@example.com"


@pytest.mark.negative
def test_me_update_payload_rejects_role_fields() -> None:
    """Assert self-service account payloads cannot include admin fields."""
    with pytest.raises(ValueError, match="role"):
        CurrentUserProfilePatchRequest.model_validate({"role": "admin"})


@pytest.mark.negative
def test_profile_payload_rejects_password_fields() -> None:
    """Keep credential changes out of the profile patch contract."""
    with pytest.raises(ValueError, match="password"):
        CurrentUserProfilePatchRequest.model_validate({"password": TEST_PASSWORD})


@pytest.mark.negative
@pytest.mark.parametrize("field", ["email", "first_name", "last_name"])
def test_profile_patch_rejects_explicit_nulls(field: str) -> None:
    """Keep omission as the only no-op signal at the HTTP PATCH boundary."""
    with pytest.raises(ValidationError, match="Explicit null is not allowed"):
        CurrentUserProfilePatchRequest.model_validate({field: None})

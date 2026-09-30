"""Tests for current-user API route handlers."""

import pytest
from app.api.v1.me.profile import change_password, delete_me, get_me, patch_me
from app.api.v1.me.schemas import (
    CurrentUserPasswordChangeRequest,
    CurrentUserProfilePatchRequest,
)
from app.browser_sessions.response_transport import (
    BrowserSessionCookieMutation,
    BrowserSessionCookieMutationKind,
)
from app.security.principals import BrowserUserPrincipalContext
from fastapi import status
from fastapi.responses import Response
from pydantic import ValidationError
from starlette.requests import Request

from tests.fixtures.api import TEST_PASSWORD
from tests.identifiers import PublicId
from tests.mocks.api import FakeUserSelfService


pytestmark = pytest.mark.unit
NEW_PASSWORD = "N3wSecretPass2!"  # noqa: S105


@pytest.mark.asyncio
async def test_me_routes_call_user_service() -> None:
    """Assert /me route handlers return service results."""
    service = FakeUserSelfService()
    user_ctx = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=1,
        raw_session_id="session",
        user_public_id=PublicId(1),
        organization_public_id=PublicId(1),
    )

    get_response = await get_me(
        _principal=user_ctx,
        user_service=service,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
    )
    patch_response = await patch_me(
        _principal=user_ctx,
        payload=CurrentUserProfilePatchRequest(email="patched@example.com"),
        user_service=service,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
    )
    assert get_response.organization.name == "Test Organization"
    assert str(patch_response.email) == "patched@example.com"


@pytest.mark.asyncio
async def test_browser_account_routes_call_user_service() -> None:
    """Assert browser-bound account handlers invoke user commands."""
    service = FakeUserSelfService()
    password_request = Request({"type": "http"})
    delete_request = Request({"type": "http"})

    password_response = await change_password(
        request=password_request,
        response=Response(),
        payload=CurrentUserPasswordChangeRequest(
            current_password=TEST_PASSWORD,
            new_password=NEW_PASSWORD,
        ),
        user_service=service,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
    )
    delete_response = await delete_me(
        request=delete_request,
        response=Response(),
        user_service=service,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
    )

    assert password_response.status_code == status.HTTP_204_NO_CONTENT
    assert service.password_changed
    assert delete_response.status_code == status.HTTP_204_NO_CONTENT
    assert service.deleted
    for request in (password_request, delete_request):
        mutation = request.state.session_cookie_mutation
        assert isinstance(mutation, BrowserSessionCookieMutation)
        assert mutation.kind == BrowserSessionCookieMutationKind.CLEAR_ON_SUCCESS


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

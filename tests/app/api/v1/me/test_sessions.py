"""Tests for current-user routes backed by browser sessions."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from app.api.v1.me.errors import CurrentSessionRequiresLogoutError
from app.api.v1.me.schemas import CurrentUserPasswordChangeRequest
from app.api.v1.me.sessions import change_password, delete_me, revoke_session
from app.browser_sessions.public_ids import format_browser_session_id
from app.browser_sessions.response_transport import (
    SessionCookieMutation,
    SessionCookieMutationKind,
)
from app.public_ids import PublicId
from app.security.dtos import BrowserUserPrincipalContext
from fastapi import status
from fastapi.responses import Response
from starlette.requests import Request

from tests.fixtures.api import TEST_PASSWORD
from tests.mocks.api import FakeUserSelfService


pytestmark = pytest.mark.unit
NEW_PASSWORD = "N3wSecretPass2!"  # noqa: S105


@pytest.mark.asyncio
async def test_session_account_routes_call_user_service() -> None:
    """Assert session-bound account handlers invoke user commands."""
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
        user_service=service,  # type: ignore[arg-type]
    )
    delete_response = await delete_me(
        request=delete_request,
        response=Response(),
        user_service=service,  # type: ignore[arg-type]
    )

    assert password_response.status_code == status.HTTP_204_NO_CONTENT
    assert service.password_changed
    assert delete_response.status_code == status.HTTP_204_NO_CONTENT
    assert service.deleted
    for request in (password_request, delete_request):
        mutation = request.state.session_cookie_mutation
        assert isinstance(mutation, SessionCookieMutation)
        assert mutation.kind == SessionCookieMutationKind.CLEAR_ON_SUCCESS


@pytest.mark.asyncio
async def test_revoke_session_rejects_current_session() -> None:
    """Require the cookie-clearing logout route for the current session."""
    public_id = PublicId(1)
    lifecycle_service = SimpleNamespace(
        get_session_csrf_state=AsyncMock(
            return_value=SimpleNamespace(public_id=public_id)
        )
    )
    revocation_service = SimpleNamespace(revoke_user_session_by_public_id=AsyncMock())
    user_ctx = BrowserUserPrincipalContext(
        user_id=1, organization_id=1, session_id="raw-session"
    )

    with pytest.raises(CurrentSessionRequiresLogoutError) as exc_info:
        await revoke_session(
            session_id=format_browser_session_id(public_id),
            lifecycle_service=lifecycle_service,  # type: ignore[arg-type]
            revocation_service=revocation_service,  # type: ignore[arg-type]
            user_ctx=user_ctx,
        )

    assert exc_info.value.status == status.HTTP_409_CONFLICT
    assert exc_info.value.code == "CURRENT_SESSION_REQUIRES_LOGOUT"
    revocation_service.revoke_user_session_by_public_id.assert_not_awaited()

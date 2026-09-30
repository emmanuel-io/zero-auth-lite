"""Tests for current-user routes backed by browser sessions."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from app.api.v1.me.errors import CurrentSessionRequiresLogoutError
from app.api.v1.me.sessions import revoke_session
from app.security.principals import BrowserUserPrincipalContext
from fastapi import status

from tests.identifiers import PublicId


pytestmark = pytest.mark.unit


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
        user_id=1,
        organization_id=1,
        raw_session_id="raw-session",
        user_public_id=PublicId(1),
        organization_public_id=PublicId(1),
    )

    with pytest.raises(CurrentSessionRequiresLogoutError) as exc_info:
        await revoke_session(
            session_id=public_id,
            lifecycle_service=lifecycle_service,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
            revocation_service=revocation_service,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
            user_ctx=user_ctx,
        )

    assert exc_info.value.status == status.HTTP_409_CONFLICT
    assert exc_info.value.code == "CURRENT_SESSION_REQUIRES_LOGOUT"
    revocation_service.revoke_user_session_by_public_id.assert_not_awaited()

"""Service-boundary tests for organization OAuth2 session administration."""

from unittest.mock import AsyncMock

import pytest
from app.core.errors.common import ForbiddenOperationError
from app.oauth2.organization_oauth2_sessions.service import (
    OrganizationOAuth2SessionService,
)
from app.security.principals import BrowserUserPrincipalContext
from sqlalchemy.ext.asyncio import AsyncSession

from tests.identifiers import deterministic_uuid, PublicId


pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_ordinary_member_cannot_read_or_revoke_through_service() -> None:
    """Reject every public operation before persistence is accessed."""

    db_session = AsyncMock(spec=AsyncSession)
    service = OrganizationOAuth2SessionService(db_session=db_session)
    member_ctx = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=2,
        raw_session_id="session",
        user_public_id=PublicId(1),
        organization_public_id=PublicId(2),
    )

    with pytest.raises(ForbiddenOperationError):
        await service.list_sessions(
            actor_ctx=member_ctx,
            client_id=None,
            grant_type=None,
            user_public_id=None,
            active_only=False,
            offset=0,
            limit=20,
        )
    with pytest.raises(ForbiddenOperationError):
        await service.revoke_client_token_families(
            client_id=deterministic_uuid("client"), actor_ctx=member_ctx
        )
    with pytest.raises(ForbiddenOperationError):
        await service.revoke_session(
            session_public_id=PublicId(0), actor_ctx=member_ctx
        )

    db_session.get.assert_not_awaited()
    db_session.scalar.assert_not_awaited()
    db_session.execute.assert_not_awaited()

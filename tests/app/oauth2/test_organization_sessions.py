"""Service-boundary tests for organization OAuth2 session administration."""

from unittest.mock import AsyncMock

import pytest
from app.enums import Role
from app.errors import ForbiddenOperationError
from app.oauth2.organization_oauth2_sessions import OrganizationOAuth2SessionService
from app.public_ids import PublicId
from app.security.dtos import BrowserUserPrincipalContext
from sqlalchemy.ext.asyncio import AsyncSession


pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_ordinary_member_cannot_read_or_revoke_through_service() -> None:
    """Reject every public operation before persistence is accessed."""
    db_session = AsyncMock(spec=AsyncSession)
    service = OrganizationOAuth2SessionService(db_session=db_session)
    member_ctx = BrowserUserPrincipalContext(
        user_id=1, organization_id=2, session_id="session"
    )

    with pytest.raises(ForbiddenOperationError):
        await service.list_sessions(
            admin_ctx=member_ctx,
            client_id=None,
            grant_type=None,
            user_public_id=None,
            active_only=False,
            offset=0,
            limit=20,
        )
    with pytest.raises(ForbiddenOperationError):
        await service.revoke_client_token_families(
            client_id="client", admin_ctx=member_ctx
        )
    with pytest.raises(ForbiddenOperationError):
        await service.revoke_session(
            session_public_id=PublicId(0), admin_ctx=member_ctx
        )

    db_session.get.assert_not_awaited()
    db_session.scalar.assert_not_awaited()
    db_session.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_session_listing_requires_loaded_organization_public_id() -> None:
    """Reject an incomplete user context instead of querying transport metadata."""
    db_session = AsyncMock(spec=AsyncSession)
    service = OrganizationOAuth2SessionService(db_session=db_session)
    admin_ctx = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=2,
        session_id="session",
        roles=frozenset({Role.ORGANIZATION_ADMIN}),
    )

    with pytest.raises(RuntimeError, match="public organization identifier"):
        await service.list_sessions(
            admin_ctx=admin_ctx,
            client_id=None,
            grant_type=None,
            user_public_id=None,
            active_only=False,
            offset=0,
            limit=20,
        )

    db_session.get.assert_not_awaited()
    db_session.scalar.assert_not_awaited()
    db_session.execute.assert_not_awaited()

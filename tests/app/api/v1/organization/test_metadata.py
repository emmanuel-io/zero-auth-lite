"""Tests for organization API route handlers."""

import pytest
from app.api.v1.organization.metadata import get_current_organization
from app.security.dtos import BrowserUserPrincipalContext

from tests.fixtures.api import TEST_ORGANIZATION_PUBLIC_ID
from tests.mocks.api import FakeOrganizationMetadataService


pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_organization_route_returns_current_organization() -> None:
    """Assert the current organization route returns the service result."""
    response = await get_current_organization(
        _principal=BrowserUserPrincipalContext(
            user_id=1, organization_id=1, session_id="session"
        ),
        organization_service=FakeOrganizationMetadataService(),  # type: ignore[arg-type]
    )

    assert response.public_id == TEST_ORGANIZATION_PUBLIC_ID
    assert response.name == "Organization"

"""Tests for operator organization API route handlers."""

import pytest
from app.api.v1.server.organizations.router import (
    create_organization,
    get_organization,
    list_organizations,
    patch_organization,
)
from app.api.v1.server.organizations.schemas import (
    ServerOrganizationCreateRequest,
    ServerOrganizationListQuery,
    ServerOrganizationPatchRequest,
)
from app.security.principals import BrowserUserPrincipalContext

from tests.fixtures.api import (
    TEST_LIST_LIMIT,
    TEST_LIST_OFFSET,
    TEST_ORGANIZATION_PUBLIC_ID,
)
from tests.identifiers import (
    PublicId,
)
from tests.mocks.api import FakeServerOrganizationsService


pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_operator_organization_routes_call_service() -> None:
    """Assert operator organization handlers return direct response models."""
    service = FakeServerOrganizationsService()
    operator_ctx = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=1,
        raw_session_id="session",
        user_public_id=PublicId(1),
        organization_public_id=PublicId(1),
        roles=frozenset(),
    )
    path_id = PublicId(TEST_ORGANIZATION_PUBLIC_ID)

    list_response = await list_organizations(
        organizations_service=service,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        _operator_ctx=operator_ctx,
        query=ServerOrganizationListQuery(
            offset=TEST_LIST_OFFSET,
            limit=TEST_LIST_LIMIT,
        ),
    )
    create_response = await create_organization(
        payload=ServerOrganizationCreateRequest(name="Created Organization"),
        organizations_service=service,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        _operator_ctx=operator_ctx,
    )
    get_response = await get_organization(
        organization_id=path_id,
        organizations_service=service,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        _operator_ctx=operator_ctx,
    )
    patch_response = await patch_organization(
        organization_id=path_id,
        payload=ServerOrganizationPatchRequest(name="Updated Organization"),
        organizations_service=service,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
        _operator_ctx=operator_ctx,
    )

    assert list_response.total == 1
    assert list_response.limit == TEST_LIST_LIMIT
    assert list_response.offset == TEST_LIST_OFFSET
    assert str(create_response.name) == "Created Organization"
    assert get_response.public_id == TEST_ORGANIZATION_PUBLIC_ID
    assert str(patch_response.name) == "Updated Organization"

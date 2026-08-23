"""Tests for operator organization API route handlers."""

import pytest
from app.api.dependencies.ids import format_organization_id
from app.api.v1.admin.organizations.router import (
    create_organization,
    get_organization,
    list_organizations,
    patch_organization,
)
from app.api.v1.admin.organizations.schemas import (
    OperatorOrganizationCreateRequest,
    OperatorOrganizationPatchRequest,
)
from app.public_ids import PublicId
from app.security.dtos import BrowserUserPrincipalContext

from tests.fixtures.api import (
    TEST_LIST_LIMIT,
    TEST_LIST_OFFSET,
    TEST_ORGANIZATION_PUBLIC_ID,
)
from tests.mocks.api import FakeOperatorOrganizationsService


pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_operator_organization_routes_call_service() -> None:
    """Assert operator organization handlers return direct response models."""
    service = FakeOperatorOrganizationsService()
    operator_ctx = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=1,
        session_id="session",
        roles=frozenset(),
    )
    path_id = format_organization_id(PublicId(TEST_ORGANIZATION_PUBLIC_ID))

    list_response = await list_organizations(
        organizations_service=service,
        _operator_ctx=operator_ctx,  # type: ignore[arg-type]
        offset=TEST_LIST_OFFSET,
        limit=TEST_LIST_LIMIT,
    )
    create_response = await create_organization(
        payload=OperatorOrganizationCreateRequest(name="Created Organization"),
        organizations_service=service,
        _operator_ctx=operator_ctx,  # type: ignore[arg-type]
    )
    get_response = await get_organization(
        organization_id=path_id,
        organizations_service=service,
        _operator_ctx=operator_ctx,  # type: ignore[arg-type]
    )
    patch_response = await patch_organization(
        organization_id=path_id,
        payload=OperatorOrganizationPatchRequest(name="Updated Organization"),
        organizations_service=service,
        _operator_ctx=operator_ctx,  # type: ignore[arg-type]
    )

    assert list_response.total == 1
    assert list_response.limit == TEST_LIST_LIMIT
    assert list_response.offset == TEST_LIST_OFFSET
    assert str(create_response.name) == "Created Organization"
    assert get_response.public_id == TEST_ORGANIZATION_PUBLIC_ID
    assert str(patch_response.name) == "Updated Organization"

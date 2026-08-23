"""Tests for operator user API route handlers."""

import pytest
from app.api.dependencies.ids import format_organization_id, format_user_id
from app.api.v1.admin.users.router import (
    create_user,
    delete_user,
    get_user,
    list_users,
    patch_user,
    replace_user,
)
from app.api.v1.admin.users.schemas import (
    OperatorUserCreateRequest,
    OperatorUserPatchRequest,
    OperatorUserReplaceRequest,
)
from app.public_ids import PublicId
from app.security.dtos import BrowserUserPrincipalContext
from fastapi import status

from tests.fixtures.api import (
    TEST_LIST_LIMIT,
    TEST_LIST_OFFSET,
    TEST_ORGANIZATION_PUBLIC_ID,
    TEST_USER_PUBLIC_ID,
)
from tests.mocks.api import FakeOperatorUsersService


pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_operator_user_routes_call_service() -> None:
    """Assert operator user handlers return direct response models."""
    service = FakeOperatorUsersService()
    operator_ctx = BrowserUserPrincipalContext(
        user_id=1, organization_id=1, session_id="session"
    )
    user_path_id = format_user_id(PublicId(TEST_USER_PUBLIC_ID))
    organization_path_id = format_organization_id(PublicId(TEST_ORGANIZATION_PUBLIC_ID))

    list_response = await list_users(
        users_service=service,  # type: ignore[arg-type]
        _operator_ctx=operator_ctx,  # type: ignore[arg-type]
        offset=TEST_LIST_OFFSET,
        limit=TEST_LIST_LIMIT,
        organization_id=organization_path_id,
    )
    create_response = await create_user(
        payload=OperatorUserCreateRequest(
            organization_id=organization_path_id,
            email="new@example.com",
        ),
        users_service=service,  # type: ignore[arg-type]
        _operator_ctx=operator_ctx,  # type: ignore[arg-type]
    )
    get_response = await get_user(
        user_id=user_path_id,
        users_service=service,  # type: ignore[arg-type]
        _operator_ctx=operator_ctx,  # type: ignore[arg-type]
    )
    patch_response = await patch_user(
        user_id=user_path_id,
        payload=OperatorUserPatchRequest(email="patched@example.com", is_operator=True),
        users_service=service,  # type: ignore[arg-type]
        _operator_ctx=operator_ctx,  # type: ignore[arg-type]
    )
    replace_response = await replace_user(
        user_id=user_path_id,
        payload=OperatorUserReplaceRequest(
            organization_id=organization_path_id,
            email="updated@example.com",
            first_name="Updated",
            last_name="User",
            is_active=True,
            role="member",
            is_operator=True,
            email_verified=True,
        ),
        users_service=service,  # type: ignore[arg-type]
        _operator_ctx=operator_ctx,  # type: ignore[arg-type]
    )
    delete_response = await delete_user(
        user_id=user_path_id,
        users_service=service,  # type: ignore[arg-type]
        _operator_ctx=operator_ctx,  # type: ignore[arg-type]
    )

    assert list_response.total == 1
    assert list_response.limit == TEST_LIST_LIMIT
    assert list_response.offset == TEST_LIST_OFFSET
    assert str(create_response.email) == "new@example.com"
    assert get_response.public_id == TEST_USER_PUBLIC_ID
    assert str(patch_response.email) == "patched@example.com"
    assert str(replace_response.email) == "updated@example.com"
    assert delete_response.status_code == status.HTTP_204_NO_CONTENT

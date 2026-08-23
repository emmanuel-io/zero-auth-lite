"""Tests for current-organization user API route handlers."""

import pytest
from app.api.dependencies.ids import format_user_id
from app.api.v1.organization.users.router import (
    add_user_to_organization,
    delete_user,
    get_user,
    list_users,
    patch_user,
    replace_user,
)
from app.api.v1.organization.users.schemas import (
    OrganizationUserCreateRequest,
    OrganizationUserPatchRequest,
    OrganizationUserReplaceRequest,
)
from app.public_ids import PublicId
from fastapi import status
from pydantic import ValidationError

from tests.fixtures.api import (
    TEST_LIST_LIMIT,
    TEST_LIST_OFFSET,
    TEST_PASSWORD,
    TEST_USER_PUBLIC_ID,
)
from tests.mocks.api import FakeOrganizationUsersService


pytestmark = pytest.mark.unit


def test_organization_user_patch_rejects_explicit_nulls() -> None:
    """Keep omission as the only no-op representation for patch fields."""
    assert OrganizationUserPatchRequest().model_dump(exclude_unset=True) == {}

    with pytest.raises(ValidationError, match="Explicit null is not allowed"):
        OrganizationUserPatchRequest.model_validate({"email": None})


@pytest.mark.parametrize(
    ("schema", "payload"),
    [
        (
            OrganizationUserCreateRequest,
            {"email": "new@example.com", "email_verified": True},
        ),
        (OrganizationUserPatchRequest, {"email_verified": True}),
        (
            OrganizationUserReplaceRequest,
            {
                "email": "new@example.com",
                "first_name": "New",
                "last_name": "User",
                "is_active": True,
                "role": "member",
                "email_verified": True,
            },
        ),
    ],
)
def test_organization_user_writes_reject_verification_state(
    schema: type[
        OrganizationUserCreateRequest
        | OrganizationUserPatchRequest
        | OrganizationUserReplaceRequest
    ],
    payload: dict[str, object],
) -> None:
    """Keep email verification outside organization-admin write contracts."""
    with pytest.raises(ValidationError, match="email_verified"):
        schema.model_validate(payload)


@pytest.mark.parametrize(
    ("schema", "payload"),
    [
        (OrganizationUserCreateRequest, {"email": "new@example.com"}),
        (OrganizationUserPatchRequest, {}),
        (
            OrganizationUserReplaceRequest,
            {
                "email": "new@example.com",
                "first_name": "New",
                "last_name": "User",
                "is_active": True,
                "role": "member",
            },
        ),
    ],
)
def test_organization_user_writes_reject_operator_state(
    schema: type[
        OrganizationUserCreateRequest
        | OrganizationUserPatchRequest
        | OrganizationUserReplaceRequest
    ],
    payload: dict[str, object],
) -> None:
    """Keep global operator state outside organization-admin write contracts."""
    with pytest.raises(ValidationError, match="is_operator"):
        schema.model_validate({**payload, "is_operator": True})


@pytest.mark.parametrize(
    "schema",
    [
        OrganizationUserCreateRequest,
        OrganizationUserPatchRequest,
        OrganizationUserReplaceRequest,
    ],
)
def test_organization_user_writes_reject_operator_as_membership_role(
    schema: type[
        OrganizationUserCreateRequest
        | OrganizationUserPatchRequest
        | OrganizationUserReplaceRequest
    ],
) -> None:
    """Keep the global operator privilege out of organization roles."""
    payload: dict[str, object] = {"role": "operator"}
    if schema is OrganizationUserCreateRequest:
        payload["email"] = "new@example.com"
    elif schema is OrganizationUserReplaceRequest:
        payload.update(
            email="new@example.com",
            first_name="New",
            last_name="User",
            is_active=True,
        )

    with pytest.raises(ValidationError, match="role"):
        schema.model_validate(payload)


@pytest.mark.asyncio
async def test_user_collection_routes_call_service() -> None:
    """Assert user collection handlers return direct response models."""
    service = FakeOrganizationUsersService()

    create_response = await add_user_to_organization(
        _admin_ctx=None,  # type: ignore[arg-type]
        payload=OrganizationUserCreateRequest(
            email="new@example.com", password=TEST_PASSWORD
        ),
        users_service=service,  # type: ignore[arg-type]
    )
    list_response = await list_users(
        users_service=service,  # type: ignore[arg-type]
        _admin_ctx=None,  # type: ignore[arg-type]
        offset=TEST_LIST_OFFSET,
        limit=TEST_LIST_LIMIT,
    )

    assert str(create_response.email) == "new@example.com"
    assert list_response.total == 1
    assert list_response.limit == TEST_LIST_LIMIT
    assert list_response.offset == TEST_LIST_OFFSET
    assert service.criteria is not None
    assert service.criteria.limit == TEST_LIST_LIMIT
    assert service.criteria.offset == TEST_LIST_OFFSET


@pytest.mark.asyncio
async def test_user_list_filters_by_active_and_verified() -> None:
    """Assert organization user list builds independent active/verified filters."""
    service = FakeOrganizationUsersService()

    await list_users(
        users_service=service,  # type: ignore[arg-type]
        _admin_ctx=None,  # type: ignore[arg-type]
        active=True,
        email_verified=False,
    )

    assert service.criteria is not None
    assert service.criteria.active is True
    assert service.criteria.email_verified is False


@pytest.mark.asyncio
async def test_user_list_sorts_by_active_and_verified() -> None:
    """Assert organization user list accepts active and verified sort keys."""
    for sort_key in (
        "active",
        "-active",
        "email_verified",
        "-email_verified",
    ):
        service = FakeOrganizationUsersService()

        await list_users(
            users_service=service,  # type: ignore[arg-type]
            _admin_ctx=None,  # type: ignore[arg-type]
            sort=sort_key,
        )

        assert service.criteria is not None
        assert service.criteria.sort == sort_key


@pytest.mark.asyncio
async def test_user_item_routes_parse_public_ids() -> None:
    """Assert user item handlers parse user path IDs before service calls."""
    service = FakeOrganizationUsersService()
    path_id = format_user_id(PublicId(TEST_USER_PUBLIC_ID))

    get_response = await get_user(
        users_service=service,  # type: ignore[arg-type]
        user_id=path_id,
        _admin_ctx=None,  # type: ignore[arg-type]
    )
    replace_response = await replace_user(
        user_id=path_id,
        _admin_ctx=None,  # type: ignore[arg-type]
        payload=OrganizationUserReplaceRequest(
            email="updated@example.com",
            first_name="Updated",
            last_name="User",
            is_active=True,
            role="member",
        ),
        users_service=service,  # type: ignore[arg-type]
    )
    patch_response = await patch_user(
        user_id=path_id,
        _admin_ctx=None,  # type: ignore[arg-type]
        payload=OrganizationUserPatchRequest(email="patched@example.com"),
        users_service=service,  # type: ignore[arg-type]
    )
    delete_response = await delete_user(
        user_id=path_id,
        _admin_ctx=None,  # type: ignore[arg-type]
        users_service=service,  # type: ignore[arg-type]
    )

    assert get_response.public_id == TEST_USER_PUBLIC_ID
    assert str(replace_response.email) == "updated@example.com"
    assert str(patch_response.email) == "patched@example.com"
    assert delete_response.status_code == status.HTTP_204_NO_CONTENT
    assert service.target == PublicId(TEST_USER_PUBLIC_ID)

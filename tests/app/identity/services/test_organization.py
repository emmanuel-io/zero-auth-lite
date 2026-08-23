"""Tests for organization-scoped user administration."""

import pytest
from app.enums import Role
from app.errors import ForbiddenOperationError, ObjectNotFoundError
from app.identity.services.organization import OrganizationUsersService
from app.identity.users.criteria import OrganizationUserSearchCriteriaDTO
from app.identity.users.dtos import OrganizationUserCreateDTO
from app.identity.users.enums import OrganizationUserRole
from app.public_ids import PublicId
from fastapi import FastAPI

from .helpers import build_lifecycle, create_organization, create_user, user_context


pytestmark = pytest.mark.integration
EXPECTED_USER_COUNT = 2


@pytest.mark.asyncio
async def test_organization_service_scopes_search_and_get(app: FastAPI) -> None:
    """Never expose a user belonging to another organization."""
    organization = await create_organization(app, name="Organization Scope")
    other = await create_organization(app, name="Other Scope")
    actor = await create_user(
        app,
        organization_id=organization.id,
        email="organization-actor@example.com",
        role=OrganizationUserRole.ADMIN,
    )
    target = await create_user(
        app,
        organization_id=organization.id,
        email="organization-target@example.com",
    )
    outsider = await create_user(
        app,
        organization_id=other.id,
        email="organization-outsider@example.com",
    )
    async with app.state.core_session_factory() as db_session:
        service = OrganizationUsersService(
            db_session=db_session,
            user_ctx=user_context(actor, role=Role.ORGANIZATION_ADMIN),
            lifecycle=build_lifecycle(app, db_session),
        )
        page = await service.search(criteria=OrganizationUserSearchCriteriaDTO())
        stable_page = await service.search(
            criteria=OrganizationUserSearchCriteriaDTO(sort="active")
        )
        with pytest.raises(ObjectNotFoundError):
            await service.get(user_id=PublicId(outsider.public_id))

    assert page.total == EXPECTED_USER_COUNT
    assert [item.public_id for item in stable_page.items] == sorted(
        [actor.public_id, target.public_id]
    )


@pytest.mark.asyncio
async def test_organization_service_requires_admin_role(app: FastAPI) -> None:
    """Reject direct service use by an ordinary organization user."""
    organization = await create_organization(app, name="Organization Guard")
    actor = await create_user(
        app,
        organization_id=organization.id,
        email="organization-user@example.com",
    )
    async with app.state.core_session_factory() as db_session:
        service = OrganizationUsersService(
            db_session=db_session,
            user_ctx=user_context(actor),
            lifecycle=build_lifecycle(app, db_session),
        )
        with pytest.raises(ForbiddenOperationError):
            await service.search(criteria=OrganizationUserSearchCriteriaDTO())


@pytest.mark.asyncio
async def test_organization_service_creates_in_actor_organization(
    app: FastAPI,
) -> None:
    """Derive the target organization exclusively from the principal."""
    organization = await create_organization(app, name="Organization Create")
    actor = await create_user(
        app,
        organization_id=organization.id,
        email="organization-create-actor@example.com",
        role=OrganizationUserRole.ADMIN,
    )
    async with app.state.core_session_factory() as db_session:
        service = OrganizationUsersService(
            db_session=db_session,
            user_ctx=user_context(actor, role=Role.ORGANIZATION_ADMIN),
            lifecycle=build_lifecycle(app, db_session),
        )
        created = await service.create(
            dto=OrganizationUserCreateDTO(email="organization-created@example.com")
        )

    assert str(created.email) == "organization-created@example.com"

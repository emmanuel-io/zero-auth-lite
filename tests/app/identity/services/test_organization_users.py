"""Tests for organization-scoped user administration."""

import pytest
from app.core.errors.common import ForbiddenOperationError, ObjectNotFoundError
from app.identity.services.organization_users import OrganizationUsersService
from app.identity.users.criteria import OrganizationUserSearchCriteriaDTO
from app.identity.users.dtos import OrganizationUserCreateDTO
from app.identity.users.enums import OrganizationMembershipRole
from app.security.roles import Role
from fastapi import FastAPI

from tests.identifiers import PublicId

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
        role=OrganizationMembershipRole.ADMIN,
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
            actor_ctx=user_context(actor, role=Role.ORGANIZATION_ADMIN),
            lifecycle=build_lifecycle(app, db_session),
        )
        page = await service.search(criteria=OrganizationUserSearchCriteriaDTO())
        stable_page = await service.search(
            criteria=OrganizationUserSearchCriteriaDTO(sort="active")
        )
        with pytest.raises(ObjectNotFoundError):
            await service.get(user_id=PublicId(outsider.public_id))

    assert page.total == EXPECTED_USER_COUNT
    assert [item.public_id for item in stable_page.items] == [
        actor.public_id,
        target.public_id,
    ]


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
            actor_ctx=user_context(actor),
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
        role=OrganizationMembershipRole.ADMIN,
    )
    async with app.state.core_session_factory() as db_session:
        service = OrganizationUsersService(
            db_session=db_session,
            actor_ctx=user_context(actor, role=Role.ORGANIZATION_ADMIN),
            lifecycle=build_lifecycle(app, db_session),
        )
        created = await service.create(
            dto=OrganizationUserCreateDTO(email="organization-created@example.com")
        )

    assert str(created.email) == "organization-created@example.com"


@pytest.mark.asyncio
async def test_organization_service_returns_session_target(app: FastAPI) -> None:
    """Return one manageable organization's session target in one lookup."""
    organization = await create_organization(app, name="Organization Session Target")
    actor = await create_user(
        app,
        organization_id=organization.id,
        email="organization-session-actor@example.com",
        role=OrganizationMembershipRole.ADMIN,
    )
    target = await create_user(
        app,
        organization_id=organization.id,
        email="organization-session-target@example.com",
    )
    async with app.state.core_session_factory() as db_session:
        service = OrganizationUsersService(
            db_session=db_session,
            actor_ctx=user_context(actor, role=Role.ORGANIZATION_ADMIN),
            lifecycle=build_lifecycle(app, db_session),
        )
        session_target = await service.get_session_target(
            user_id=PublicId(target.public_id)
        )

    assert session_target.internal_user_id == target.id
    assert str(session_target.email) == target.email

"""Tests for server-operator user administration."""

import pytest
from app.core.errors.common import ForbiddenOperationError
from app.identity.services.server_users import ServerUsersService
from app.identity.users.criteria import ServerUserSearchCriteriaDTO
from app.identity.users.dtos import ServerUserCreateDTO
from app.security.roles import Role
from fastapi import FastAPI

from tests.identifiers import PublicId

from .helpers import build_lifecycle, create_organization, create_user, user_context


pytestmark = pytest.mark.integration
EXPECTED_USER_COUNT = 2


@pytest.mark.asyncio
async def test_operator_service_searches_across_organizations(app: FastAPI) -> None:
    """Return organization identifiers without per-user follow-up queries."""
    first = await create_organization(app, name="Operator First")
    second = await create_organization(app, name="Operator Second")
    actor = await create_user(
        app,
        organization_id=first.id,
        email="operator-actor@example.com",
        is_operator=True,
    )
    target = await create_user(
        app,
        organization_id=second.id,
        email="operator-target@example.com",
    )
    async with app.state.core_session_factory() as db_session:
        service = ServerUsersService(
            db_session=db_session,
            actor_ctx=user_context(actor, role=Role.OPERATOR),
            lifecycle=build_lifecycle(app, db_session),
        )
        page = await service.search(criteria=ServerUserSearchCriteriaDTO())
        stable_page = await service.search(
            criteria=ServerUserSearchCriteriaDTO(sort="active")
        )

    assert page.total == EXPECTED_USER_COUNT
    assert {item.organization_public_id for item in page.items}
    assert [item.public_id for item in stable_page.items] == [
        actor.public_id,
        target.public_id,
    ]


@pytest.mark.asyncio
async def test_operator_service_requires_operator_role(app: FastAPI) -> None:
    """Reject direct global administration by an ordinary user."""
    organization = await create_organization(app, name="Operator Guard")
    actor = await create_user(
        app,
        organization_id=organization.id,
        email="operator-ordinary@example.com",
    )
    async with app.state.core_session_factory() as db_session:
        service = ServerUsersService(
            db_session=db_session,
            actor_ctx=user_context(actor),
            lifecycle=build_lifecycle(app, db_session),
        )
        with pytest.raises(ForbiddenOperationError):
            await service.search(criteria=ServerUserSearchCriteriaDTO())


@pytest.mark.asyncio
async def test_operator_service_selects_target_organization(app: FastAPI) -> None:
    """Resolve only public organization identifiers at the operator boundary."""
    first = await create_organization(app, name="Operator Actor Organization")
    target = await create_organization(app, name="Operator Target Organization")
    actor = await create_user(
        app,
        organization_id=first.id,
        email="operator-create@example.com",
        is_operator=True,
    )
    async with app.state.core_session_factory() as db_session:
        service = ServerUsersService(
            db_session=db_session,
            actor_ctx=user_context(actor, role=Role.OPERATOR),
            lifecycle=build_lifecycle(app, db_session),
        )
        created = await service.create(
            dto=ServerUserCreateDTO(
                organization_id=PublicId(target.public_id),
                email="operator-created@example.com",
            ),
        )

    assert created.organization_public_id is not None


@pytest.mark.asyncio
async def test_operator_service_returns_session_target(app: FastAPI) -> None:
    """Return the internal identifier and email in one authorized lookup."""
    organization = await create_organization(app, name="Operator Session Target")
    actor = await create_user(
        app,
        organization_id=organization.id,
        email="operator-session-actor@example.com",
        is_operator=True,
    )
    target = await create_user(
        app,
        organization_id=organization.id,
        email="operator-session-target@example.com",
    )
    async with app.state.core_session_factory() as db_session:
        service = ServerUsersService(
            db_session=db_session,
            actor_ctx=user_context(actor, role=Role.OPERATOR),
            lifecycle=build_lifecycle(app, db_session),
        )
        session_target = await service.get_session_target(
            user_id=PublicId(target.public_id)
        )

    assert session_target.internal_user_id == target.id
    assert str(session_target.email) == target.email

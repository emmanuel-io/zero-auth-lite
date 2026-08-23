"""Tests for organization metadata behavior at actor-focused boundaries."""

import pytest
from app.db.errors import CheckViolationError
from app.db.models.organization import OrganizationDB
from app.enums import Role
from app.errors import ForbiddenOperationError, ObjectNotFoundError
from app.identity.organizations.dtos import OrganizationCreateDTO, OrganizationUpdateDTO
from app.identity.services.operator_organizations import OperatorOrganizationsService
from app.identity.services.organization_metadata import OrganizationMetadataService
from app.public_ids import PublicId
from app.security.dtos import BrowserUserPrincipalContext
from fastapi import FastAPI
from sqlalchemy import func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession


pytestmark = pytest.mark.integration
EXPECTED_SHARED_NAME_COUNT = 2


class RefreshFailureError(RuntimeError):
    """Synthetic persistence refresh failure used by transaction tests."""


def organization_service(
    db_session: AsyncSession,
    *,
    organization_id: int,
) -> OrganizationMetadataService:
    """Build an organization-scoped service for metadata tests."""
    return OrganizationMetadataService(
        db_session=db_session,
        user_ctx=BrowserUserPrincipalContext(
            user_id=1,
            organization_id=organization_id,
            session_id="session",
            roles=frozenset({Role.ORGANIZATION_ADMIN}),
        ),
    )


def operator_service(
    db_session: AsyncSession, *, organization_id: int
) -> OperatorOrganizationsService:
    """Build an operator-scoped service for organization metadata tests."""
    return OperatorOrganizationsService(
        db_session=db_session,
        user_ctx=BrowserUserPrincipalContext(
            user_id=1,
            organization_id=organization_id,
            session_id="session",
            roles=frozenset({Role.OPERATOR}),
        ),
    )


@pytest.mark.asyncio
async def test_get_organization_returns_current_organization(app: FastAPI) -> None:
    """Return the organization selected by the current principal."""
    async with app.state.core_session_factory() as db_session:
        organization = (
            await db_session.execute(
                insert(OrganizationDB)
                .values(name="Service Organization")
                .returning(OrganizationDB)
            )
        ).scalar_one()
        await db_session.commit()
        service = organization_service(
            db_session,
            organization_id=organization.id,
        )
        result = await service.get()

    assert result.public_id == organization.public_id
    assert result.name == "Service Organization"


@pytest.mark.asyncio
async def test_get_organization_raises_when_missing(app: FastAPI) -> None:
    """Raise when the current organization no longer exists."""
    async with app.state.core_session_factory() as db_session:
        service = organization_service(
            db_session,
            organization_id=999999,
        )
        with pytest.raises(ObjectNotFoundError):
            await service.get()


@pytest.mark.asyncio
async def test_create_organization_leaves_commit_to_the_caller(app: FastAPI) -> None:
    """Allow a caller-owned transaction to roll back organization creation."""
    async with app.state.core_session_factory() as db_session:
        service = operator_service(db_session, organization_id=1)
        await service.create(dto=OrganizationCreateDTO(name="Composed Organization"))
        await db_session.rollback()

    async with app.state.core_session_factory() as db_session:
        count = await db_session.scalar(
            select(func.count())
            .select_from(OrganizationDB)
            .where(OrganizationDB.name == "Composed Organization")
        )
    assert count == 0


@pytest.mark.asyncio
async def test_organizations_can_share_the_same_name(app: FastAPI) -> None:
    """Treat organization names as display labels rather than identifiers."""
    async with app.state.core_session_factory() as db_session:
        current_organization = (
            await db_session.execute(
                insert(OrganizationDB)
                .values(name="Current organization")
                .returning(OrganizationDB)
            )
        ).scalar_one()
        await db_session.execute(insert(OrganizationDB).values(name="Shared name"))
        await db_session.commit()
        service = organization_service(
            db_session,
            organization_id=current_organization.id,
        )
        updated = await service.update(dto=OrganizationUpdateDTO(name="Shared name"))
        await db_session.commit()

    assert updated.name == "Shared name"
    async with app.state.core_session_factory() as db_session:
        count = await db_session.scalar(
            select(func.count())
            .select_from(OrganizationDB)
            .where(OrganizationDB.name == "Shared name")
        )
    assert count == EXPECTED_SHARED_NAME_COUNT


@pytest.mark.asyncio
async def test_organization_integrity_error_preserves_callers_transaction(
    app: FastAPI,
) -> None:
    """Rollback only an update rejected by a database invariant."""
    async with app.state.core_session_factory() as db_session:
        current_organization = (
            await db_session.execute(
                insert(OrganizationDB)
                .values(name="Current organization")
                .returning(OrganizationDB)
            )
        ).scalar_one()
        await db_session.commit()
        service = organization_service(
            db_session,
            organization_id=current_organization.id,
        )
        db_session.add(OrganizationDB(name="Caller-owned organization"))
        invalid_update = OrganizationUpdateDTO.model_construct(name="   ")

        with pytest.raises(CheckViolationError):
            await service.update(dto=invalid_update)
        await db_session.commit()

    async with app.state.core_session_factory() as db_session:
        names = set(await db_session.scalars(select(OrganizationDB.name)))
    assert "Current organization" in names
    assert "Caller-owned organization" in names


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ["organization", "operator"])
async def test_organization_update_is_reversible_when_refresh_fails(
    app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
) -> None:
    """Leave a failed update reversible by the caller-owned transaction."""
    async with app.state.core_session_factory() as db_session:
        organization = (
            await db_session.execute(
                insert(OrganizationDB)
                .values(name="Original organization")
                .returning(OrganizationDB)
            )
        ).scalar_one()
        organization_id = organization.id
        organization_public_id = PublicId(organization.public_id)
        await db_session.commit()

        async def fail_refresh(_row: object) -> None:
            raise RefreshFailureError

        monkeypatch.setattr(db_session, "refresh", fail_refresh)
        if surface == "organization":
            metadata_service = organization_service(
                db_session,
                organization_id=organization_id,
            )
            update = metadata_service.update(
                dto=OrganizationUpdateDTO(name="Updated organization")
            )
        else:
            organizations_service = operator_service(
                db_session, organization_id=organization_id
            )
            update = organizations_service.update(
                organization_id=organization_public_id,
                dto=OrganizationUpdateDTO(name="Updated organization"),
            )
        with pytest.raises(RefreshFailureError):
            await update
        await db_session.rollback()

    async with app.state.core_session_factory() as db_session:
        persisted_name = await db_session.scalar(
            select(OrganizationDB.name).where(OrganizationDB.id == organization_id)
        )
    assert persisted_name == "Original organization"


@pytest.mark.asyncio
@pytest.mark.negative
@pytest.mark.parametrize("operation", ["read", "update"])
async def test_organization_metadata_requires_organization_admin_role(
    app: FastAPI, operation: str
) -> None:
    """Keep organization-admin enforcement inside the service boundary."""
    async with app.state.core_session_factory() as db_session:
        service = OrganizationMetadataService(
            db_session=db_session,
            user_ctx=BrowserUserPrincipalContext(
                user_id=1, organization_id=1, session_id="session"
            ),
        )
        operation_call = (
            service.get()
            if operation == "read"
            else service.update(dto=OrganizationUpdateDTO(name="Forbidden update"))
        )
        with pytest.raises(ForbiddenOperationError):
            await operation_call

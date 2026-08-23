"""Tests for current-user self-service."""

import pytest
from app.identity.errors import CurrentPasswordMismatchError
from app.identity.services.self import UserSelfService
from app.identity.users.dtos import UserPasswordChangeDTO, UserSelfPatchDTO
from fastapi import FastAPI

from .helpers import (
    build_lifecycle,
    create_organization,
    create_user,
    TEST_PASSWORD,
    user_context,
)


pytestmark = pytest.mark.integration
NEW_PASSWORD = "N3wS3cretPass1!"  # noqa: S105
WRONG_PASSWORD = "wrong-password"  # noqa: S105


@pytest.mark.asyncio
async def test_self_service_reads_and_patches_only_current_user(app: FastAPI) -> None:
    """Return public organization data and stage email changes for verification."""
    organization = await create_organization(app, name="Self Service")
    actor = await create_user(
        app,
        organization_id=organization.id,
        email="self-service@example.com",
    )
    async with app.state.core_session_factory() as db_session:
        service = UserSelfService(
            db_session=db_session,
            user_ctx=user_context(actor),
            lifecycle=build_lifecycle(app, db_session),
        )
        before = await service.read()
        after = await service.patch(
            data=UserSelfPatchDTO(email="self-service-new@example.com")
        )

    assert before.organization.name == organization.name
    assert str(after.email) == "self-service@example.com"
    assert str(after.pending_email) == "self-service-new@example.com"


@pytest.mark.asyncio
async def test_self_service_rejects_wrong_current_password(app: FastAPI) -> None:
    """Require the persisted credential before changing a password."""
    organization = await create_organization(app, name="Self Password")
    actor = await create_user(
        app,
        organization_id=organization.id,
        email="self-password@example.com",
    )
    async with app.state.core_session_factory() as db_session:
        service = UserSelfService(
            db_session=db_session,
            user_ctx=user_context(actor),
            lifecycle=build_lifecycle(app, db_session),
        )
        with pytest.raises(CurrentPasswordMismatchError):
            await service.change_password(
                data=UserPasswordChangeDTO(
                    current_password=WRONG_PASSWORD,
                    new_password=NEW_PASSWORD,
                )
            )


@pytest.mark.asyncio
async def test_self_service_changes_password(app: FastAPI) -> None:
    """Delegate password replacement through the shared lifecycle."""
    organization = await create_organization(app, name="Self Password Change")
    actor = await create_user(
        app,
        organization_id=organization.id,
        email="self-password-change@example.com",
    )
    async with app.state.core_session_factory() as db_session:
        service = UserSelfService(
            db_session=db_session,
            user_ctx=user_context(actor),
            lifecycle=build_lifecycle(app, db_session),
        )
        await service.change_password(
            data=UserPasswordChangeDTO(
                current_password=TEST_PASSWORD,
                new_password=NEW_PASSWORD,
            )
        )

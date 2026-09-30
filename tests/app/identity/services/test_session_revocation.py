"""Tests for user changes that revoke browser and OAuth2 sessions."""

from datetime import datetime, UTC

import httpx
import pytest
from app.db.models.browser_session import BrowserSessionDB
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_state import OAuth2TokenStateDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.db.models.workflow_token import UserWorkflowTokenDB
from app.identity.services.self import UserSelfService
from app.identity.services.server_users import ServerUsersService
from app.identity.users.dtos import ServerUserPatchDTO, UserPasswordChangeDTO
from app.identity.users.emails import active_email_loader
from app.identity.users.enums import OrganizationMembershipRole, UserEmailStatus
from app.security.principals import BrowserUserPrincipalContext
from app.security.roles import Role
from app.workflow_tokens.enums import WorkflowTokenPurpose
from app.workflow_tokens.service import WorkflowTokenService
from app.workflow_tokens.settings import WorkflowTokenSettings
from fastapi import FastAPI, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.fixtures.auth import issue_user_token, login_browser, UserCredentials
from tests.identifiers import PublicId

from .helpers import build_lifecycle, CreatedUser, user_context


pytestmark = pytest.mark.integration
NEW_TEST_PASSWORD = "N3wS3cretPass1!"  # noqa: S105


type AuthenticationStateModel = type[
    BrowserSessionDB | OAuth2SessionDB | OAuth2TokenStateDB | UserWorkflowTokenDB
]


async def _count(app: FastAPI, model: AuthenticationStateModel) -> int:
    """Count rows for one persisted authentication model."""
    async with app.state.core_session_factory() as db_session:
        return int(
            await db_session.scalar(select(func.count()).select_from(model)) or 0
        )


async def _count_revoked_sessions(app: FastAPI) -> int:
    """Count revoked browser sessions."""
    async with app.state.core_session_factory() as db_session:
        return int(
            await db_session.scalar(
                select(func.count())
                .select_from(BrowserSessionDB)
                .where(BrowserSessionDB.revoked_at.is_not(None))
            )
            or 0
        )


async def _count_ended_oauth2_sessions(app: FastAPI) -> int:
    """Count ended OAuth2 sessions."""
    async with app.state.core_session_factory() as db_session:
        return int(
            await db_session.scalar(
                select(func.count())
                .select_from(OAuth2SessionDB)
                .where(OAuth2SessionDB.ended_at.is_not(None))
            )
            or 0
        )


async def _get_user(app: FastAPI, *, email: str) -> CreatedUser:
    """Read a test user by email."""
    async with app.state.core_session_factory() as db_session:
        row = (
            await db_session.execute(
                select(UserDB, OrganizationMembershipDB)
                .join(
                    OrganizationMembershipDB,
                    OrganizationMembershipDB.user_id == UserDB.id,
                )
                .join(UserEmailDB, UserEmailDB.user_id == UserDB.id)
                .where(UserEmailDB.normalized_email == email.lower())
                .options(active_email_loader())
            )
        ).one_or_none()
    assert row is not None
    user, membership = row
    return CreatedUser(user=user, membership=membership)


async def _add_backup_admin(app: FastAPI, *, user: CreatedUser) -> None:
    """Keep organization and operator access available during mutations."""
    async with app.state.core_session_factory() as db_session:
        backup = UserDB(
            hashed_password=user.user.hashed_password,
            is_active=True,
            is_operator=True,
        )
        db_session.add(backup)
        await db_session.flush()
        db_session.add_all(
            [
                UserEmailDB(
                    user_id=backup.id,
                    email="backup-admin@example.com",
                    normalized_email="backup-admin@example.com",
                    status=UserEmailStatus.CURRENT,
                    verified_at=datetime.now(UTC),
                ),
                OrganizationMembershipDB(
                    user_id=backup.id,
                    organization_id=user.membership.organization_id,
                    role=OrganizationMembershipRole.ADMIN,
                ),
            ]
        )
        await db_session.commit()


def _server_users_service(
    app: FastAPI, db_session: AsyncSession, user: CreatedUser
) -> ServerUsersService:
    """Build combined-role operator administration for a seeded user."""
    return ServerUsersService(
        db_session=db_session,
        actor_ctx=BrowserUserPrincipalContext(
            user_id=user.id,
            organization_id=user.membership.organization_id,
            raw_session_id="test-session",
            user_public_id=PublicId(user.public_id),
            organization_public_id=PublicId(user.membership.organization_id),
            roles=frozenset({Role.OPERATOR, Role.ORGANIZATION_ADMIN}),
        ),
        lifecycle=build_lifecycle(app, db_session),
    )


@pytest.mark.asyncio
async def test_password_change_revokes_existing_browser_sessions(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Revoke existing browser sessions after a password change."""
    response = await login_browser(client, verified_user_credentials)
    assert response.status_code == status.HTTP_204_NO_CONTENT
    user = await _get_user(app, email=verified_user_credentials.email)
    async with app.state.core_session_factory() as db_session:
        service = UserSelfService(
            db_session=db_session,
            user_ctx=user_context(user),
            lifecycle=build_lifecycle(app, db_session),
        )
        await service.change_password(
            data=UserPasswordChangeDTO(
                current_password=verified_user_credentials.password,
                new_password=NEW_TEST_PASSWORD,
            )
        )
        await db_session.commit()

    assert await _count(app, BrowserSessionDB) == 1
    assert await _count_revoked_sessions(app) == 1


@pytest.mark.asyncio
async def test_password_change_revokes_oauth2_token_family(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """End OAuth2 sessions and delete token states after a password change."""
    response = await issue_user_token(app, client, verified_user_credentials)
    assert response.status_code == status.HTTP_200_OK
    user = await _get_user(app, email=verified_user_credentials.email)
    async with app.state.core_session_factory() as db_session:
        service = UserSelfService(
            db_session=db_session,
            user_ctx=user_context(user),
            lifecycle=build_lifecycle(app, db_session),
        )
        await service.change_password(
            data=UserPasswordChangeDTO(
                current_password=verified_user_credentials.password,
                new_password=NEW_TEST_PASSWORD,
            )
        )
        await db_session.commit()

    assert await _count(app, OAuth2TokenStateDB) == 0
    assert await _count_ended_oauth2_sessions(app) == 1


@pytest.mark.asyncio
async def test_password_change_invalidates_reset_tokens(
    app: FastAPI,
    verified_user_credentials: UserCredentials,
) -> None:
    """Prevent an older recovery link from replacing a new password."""
    user = await _get_user(app, email=verified_user_credentials.email)
    async with app.state.core_session_factory() as db_session:
        await WorkflowTokenService(
            db_session=db_session,
            settings=app.state.settings.identity_workflow.workflow_tokens,
        ).issue_token_for_event(
            event_id="1" * 32,
            event_occurred_at=datetime.now(UTC),
            user_email_id=user.user.current_email.id,
            purpose=WorkflowTokenPurpose.RESET_PASSWORD,
        )
        await db_session.commit()
    async with app.state.core_session_factory() as db_session:
        service = UserSelfService(
            db_session=db_session,
            user_ctx=user_context(user),
            lifecycle=build_lifecycle(app, db_session),
        )
        await service.change_password(
            data=UserPasswordChangeDTO(
                current_password=verified_user_credentials.password,
                new_password=NEW_TEST_PASSWORD,
            )
        )
    async with app.state.core_session_factory() as db_session:
        token = await db_session.scalar(select(UserWorkflowTokenDB))

    assert token is not None
    assert token.used_at is not None


@pytest.mark.asyncio
async def test_disabling_user_revokes_sessions_and_all_workflow_tokens(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Revoke sessions and invalidate every workflow during deactivation."""
    response = await login_browser(client, verified_user_credentials)
    assert response.status_code == status.HTTP_204_NO_CONTENT
    user = await _get_user(app, email=verified_user_credentials.email)
    await _add_backup_admin(app, user=user)
    async with app.state.core_session_factory() as db_session:
        token_service = WorkflowTokenService(
            db_session=db_session,
            settings=app.state.settings.identity_workflow.workflow_tokens,
        )
        for event_number, purpose in enumerate(WorkflowTokenPurpose, start=1):
            await token_service.issue_token_for_event(
                event_id=f"{event_number:032x}",
                event_occurred_at=datetime.now(UTC),
                user_email_id=user.user.current_email.id,
                purpose=purpose,
            )
        await db_session.commit()
    async with app.state.core_session_factory() as db_session:
        service = _server_users_service(app, db_session, user)
        await service.patch(
            user_id=PublicId(user.public_id),
            dto=ServerUserPatchDTO(is_active=False),
        )
        await db_session.commit()
    async with app.state.core_session_factory() as db_session:
        tokens = list(await db_session.scalars(select(UserWorkflowTokenDB)))

    assert await _count_revoked_sessions(app) == 1
    assert {token.purpose for token in tokens} == set(WorkflowTokenPurpose)
    assert all(token.used_at is not None for token in tokens)


@pytest.mark.asyncio
async def test_role_change_revokes_existing_security_sessions(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Invalidate browser and OAuth2 authority after a role change."""
    assert (
        await login_browser(client, verified_user_credentials)
    ).status_code == status.HTTP_204_NO_CONTENT
    assert (
        await issue_user_token(app, client, verified_user_credentials)
    ).status_code == status.HTTP_200_OK
    user = await _get_user(app, email=verified_user_credentials.email)
    await _add_backup_admin(app, user=user)
    async with app.state.core_session_factory() as db_session:
        service = _server_users_service(app, db_session, user)
        await service.patch(
            user_id=PublicId(user.public_id),
            dto=ServerUserPatchDTO(role=OrganizationMembershipRole.MEMBER),
        )
        await db_session.commit()

    assert await _count_revoked_sessions(app) == 1
    assert await _count(app, OAuth2TokenStateDB) == 0
    assert await _count_ended_oauth2_sessions(app) == 1


@pytest.mark.asyncio
async def test_deleting_user_cascades_owned_authentication_state(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Cascade user deletion to browser, workflow, and OAuth2 state."""
    assert (
        await login_browser(client, verified_user_credentials)
    ).status_code == status.HTTP_204_NO_CONTENT
    assert (
        await issue_user_token(app, client, verified_user_credentials)
    ).status_code == status.HTTP_200_OK
    user = await _get_user(app, email=verified_user_credentials.email)
    await _add_backup_admin(app, user=user)
    async with app.state.core_session_factory() as db_session:
        await WorkflowTokenService(
            db_session=db_session,
            settings=WorkflowTokenSettings(),
        ).issue_token_for_event(
            event_id="1" * 32,
            event_occurred_at=datetime.now(UTC),
            user_email_id=user.user.current_email.id,
            purpose=WorkflowTokenPurpose.RESET_PASSWORD,
        )
        await db_session.commit()
    async with app.state.core_session_factory() as db_session:
        service = _server_users_service(app, db_session, user)
        await service.delete(user_id=PublicId(user.public_id))
        await db_session.commit()

    assert await _count(app, BrowserSessionDB) == 0
    assert await _count(app, UserWorkflowTokenDB) == 0
    assert await _count(app, OAuth2TokenStateDB) == 0
    assert await _count(app, OAuth2SessionDB) == 0

"""Black-box tests for workflow token workflows across auth routes."""

from unittest.mock import patch

import httpx
import pytest
from app.db.models.user import UserDB, UserEmailDB
from app.db.models.workflow_token import UserWorkflowTokenDB
from app.identity.users.emails import active_email_loader
from app.identity.users.enums import UserEmailStatus
from app.notifications.dispatcher import dispatch_pending_once
from app.workflow_tokens.enums import WorkflowTokenPurpose
from fastapi import FastAPI, status
from sqlalchemy import select, update

from tests.fixtures.auth import login_browser, UserCredentials
from tests.fixtures.routes import BrowserClientFactory
from tests.fixtures.workflow_tokens import notification_token, SuccessfulMailService
from tests.routes.api.helpers import login_headers


pytestmark = pytest.mark.api

AUTH_PATH = "/api/v1/auth"
TEST_PASSWORD = "S3cretPass1!"  # noqa: S105


@pytest.mark.asyncio
@pytest.mark.system
async def test_registered_user_can_verify_email(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert registration issues a consumable, single-use verification token."""
    register_response = await client.post(
        f"{AUTH_PATH}/register",
        json={
            "email": "verify@example.com",
            "password": "V3rifySecret1!",
            "organization_name": "Verification Workflow",
        },
    )
    assert register_response.status_code == status.HTTP_201_CREATED
    raw_token = await notification_token(app, WorkflowTokenPurpose.VERIFY_EMAIL)

    confirm_response = await client.post(
        f"{AUTH_PATH}/email/verify/confirm",
        json={"token": raw_token},
    )
    reused_response = await client.post(
        f"{AUTH_PATH}/email/verify/confirm",
        json={"token": raw_token},
    )

    assert confirm_response.status_code == status.HTTP_204_NO_CONTENT
    assert confirm_response.content == b""
    assert reused_response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.asyncio
@pytest.mark.system
@pytest.mark.negative
async def test_inactive_registered_user_cannot_verify_email(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Reject a verification link after the account becomes inactive."""
    email = "inactive-verification@example.com"
    register_response = await client.post(
        f"{AUTH_PATH}/register",
        json={
            "email": email,
            "password": "V3rifySecret1!",
            "organization_name": "Inactive Verification",
        },
    )
    raw_token = await notification_token(app, WorkflowTokenPurpose.VERIFY_EMAIL)
    async with app.state.core_session_factory.begin() as db_session:
        await db_session.execute(
            update(UserDB)
            .where(
                UserDB.id
                == select(UserEmailDB.user_id)
                .where(UserEmailDB.normalized_email == email)
                .scalar_subquery()
            )
            .values(is_active=False)
        )

    confirm_response = await client.post(
        f"{AUTH_PATH}/email/verify/confirm",
        json={"token": raw_token},
    )
    async with app.state.core_session_factory() as db_session:
        verified_at = await db_session.scalar(
            select(UserEmailDB.verified_at).where(
                UserEmailDB.normalized_email == email,
                UserEmailDB.status == UserEmailStatus.CURRENT,
            )
        )

    assert register_response.status_code == status.HTTP_201_CREATED
    assert confirm_response.status_code == status.HTTP_400_BAD_REQUEST
    assert confirm_response.json()["code"] == "INVALID_WORKFLOW_TOKEN"
    assert verified_at is None


@pytest.mark.asyncio
@pytest.mark.system
async def test_user_can_confirm_an_email_change_through_its_dedicated_route(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Keep email-change confirmation available outside self-registration."""
    headers = await login_headers(client, verified_user_credentials)
    patch_response = await client.patch(
        "/api/v1/me",
        json={"email": "changed@example.com"},
        headers=headers,
    )
    raw_token = await notification_token(app, WorkflowTokenPurpose.EMAIL_CHANGE)

    confirm_response = await client.post(
        f"{AUTH_PATH}/email/change/confirm",
        json={"token": raw_token},
    )

    async with app.state.core_session_factory() as db_session:
        changed_user = await db_session.scalar(
            select(UserDB)
            .options(active_email_loader())
            .join(UserEmailDB, UserEmailDB.user_id == UserDB.id)
            .where(
                UserEmailDB.normalized_email == "changed@example.com",
                UserEmailDB.status == UserEmailStatus.CURRENT,
            )
        )

    assert patch_response.status_code == status.HTTP_200_OK
    assert confirm_response.status_code == status.HTTP_204_NO_CONTENT
    assert changed_user is not None
    assert changed_user.pending_email is None
    assert changed_user.email_verified is True


@pytest.mark.asyncio
@pytest.mark.system
@pytest.mark.negative
async def test_inactive_user_cannot_confirm_an_email_change(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Keep current and pending addresses unchanged after deactivation."""
    headers = await login_headers(client, verified_user_credentials)
    pending_email = "inactive-change@example.com"
    patch_response = await client.patch(
        "/api/v1/me",
        json={"email": pending_email},
        headers=headers,
    )
    raw_token = await notification_token(app, WorkflowTokenPurpose.EMAIL_CHANGE)
    async with app.state.core_session_factory.begin() as db_session:
        await db_session.execute(
            update(UserDB)
            .where(
                UserDB.id
                == select(UserEmailDB.user_id)
                .where(
                    UserEmailDB.normalized_email
                    == verified_user_credentials.email.lower(),
                    UserEmailDB.status == UserEmailStatus.CURRENT,
                )
                .scalar_subquery()
            )
            .values(is_active=False)
        )

    confirm_response = await client.post(
        f"{AUTH_PATH}/email/change/confirm",
        json={"token": raw_token},
    )
    async with app.state.core_session_factory() as db_session:
        pending = await db_session.scalar(
            select(UserEmailDB).where(
                UserEmailDB.normalized_email == pending_email,
                UserEmailDB.status == UserEmailStatus.PENDING,
            )
        )
        current = await db_session.scalar(
            select(UserEmailDB).where(
                UserEmailDB.normalized_email == verified_user_credentials.email.lower(),
                UserEmailDB.status == UserEmailStatus.CURRENT,
            )
        )

    assert patch_response.status_code == status.HTTP_200_OK
    assert confirm_response.status_code == status.HTTP_400_BAD_REQUEST
    assert confirm_response.json()["code"] == "INVALID_WORKFLOW_TOKEN"
    assert pending is not None
    assert pending.verified_at is None
    assert current is not None


@pytest.mark.asyncio
@pytest.mark.system
async def test_password_reset_changes_login_credential(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Assert reset proves an unverified email and changes its credential."""
    email = "reset-unverified@example.com"
    register_response = await client.post(
        f"{AUTH_PATH}/register",
        json={
            "email": email,
            "password": "B3foreReset1!",
            "organization_name": "Reset Workflow",
        },
    )
    request_response = await client.post(
        f"{AUTH_PATH}/password/forgot",
        json={"email": email},
    )
    raw_token = await notification_token(app, WorkflowTokenPurpose.RESET_PASSWORD)
    reset_response = await client.post(
        f"{AUTH_PATH}/password/reset",
        json={"token": raw_token, "password": "R3setSecret2!"},
    )
    login_response = await login_browser(
        client,
        UserCredentials(email=email, password="R3setSecret2!"),  # noqa: S106
    )

    assert register_response.status_code == status.HTTP_201_CREATED
    assert request_response.status_code == status.HTTP_204_NO_CONTENT
    assert request_response.content == b""
    assert reset_response.status_code == status.HTTP_204_NO_CONTENT
    assert reset_response.content == b""
    assert login_response.status_code == status.HTTP_204_NO_CONTENT


@pytest.mark.asyncio
@pytest.mark.negative
async def test_inactive_user_cannot_obtain_a_password_reset_token(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Keep the public response opaque while suppressing inactive-user resets."""
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(UserDB)
            .where(
                UserDB.id
                == select(UserEmailDB.user_id)
                .where(
                    UserEmailDB.normalized_email
                    == verified_user_credentials.email.lower(),
                    UserEmailDB.status == UserEmailStatus.CURRENT,
                )
                .scalar_subquery()
            )
            .values(is_active=False)
        )
        await db_session.commit()

    response = await client.post(
        f"{AUTH_PATH}/password/forgot",
        json={"email": verified_user_credentials.email},
    )
    settings = app.state.settings.model_copy(
        update={"mail": app.state.settings.mail.model_copy(update={"enabled": True})}
    )
    with patch(
        "app.notifications.dispatcher.build_mail_service",
        return_value=SuccessfulMailService(),
    ):
        await dispatch_pending_once(app.state.core_session_factory, settings)
    async with app.state.core_session_factory() as db_session:
        token = await db_session.scalar(
            select(UserWorkflowTokenDB).where(
                UserWorkflowTokenDB.purpose == WorkflowTokenPurpose.RESET_PASSWORD
            )
        )

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert response.content == b""
    assert token is None


@pytest.mark.asyncio
@pytest.mark.system
async def test_invited_user_can_accept_invite(
    app: FastAPI,
    client: httpx.AsyncClient,
    browser_client_factory: BrowserClientFactory,
    verified_user_credentials: UserCredentials,
) -> None:
    """Assert organization-user creation without a password issues an invite token."""
    headers = await login_headers(client, verified_user_credentials)
    create_response = await client.post(
        "/api/v1/organization/users",
        json={"email": "invited@example.com"},
        headers=headers,
    )
    assert create_response.status_code == status.HTTP_201_CREATED
    initial_token = await notification_token(app, WorkflowTokenPurpose.INVITE)
    resend_response = await client.post(
        f"/api/v1/organization/users/{create_response.json()['id']}/invitation",
        headers=headers,
    )
    replacement_token = await notification_token(app, WorkflowTokenPurpose.INVITE)

    replaced_response = await client.post(
        f"{AUTH_PATH}/invite/accept",
        json={"token": initial_token, "password": "Inv1tedSecret2!"},
    )
    accept_response = await client.post(
        f"{AUTH_PATH}/invite/accept",
        json={"token": replacement_token, "password": "Inv1tedSecret2!"},
    )
    async with browser_client_factory() as invited_browser:
        login_response = await login_browser(
            invited_browser,
            UserCredentials(
                email="invited@example.com",
                password="Inv1tedSecret2!",  # noqa: S106
            ),
        )

    assert resend_response.status_code == status.HTTP_204_NO_CONTENT
    assert replaced_response.status_code == status.HTTP_400_BAD_REQUEST
    assert accept_response.status_code == status.HTTP_204_NO_CONTENT
    assert accept_response.content == b""
    assert login_response.status_code == status.HTTP_204_NO_CONTENT


@pytest.mark.asyncio
@pytest.mark.system
async def test_operator_invited_user_can_accept_invite(
    app: FastAPI,
    client: httpx.AsyncClient,
    browser_client_factory: BrowserClientFactory,
    verified_user_credentials: UserCredentials,
) -> None:
    """Complete the invitation issued by server-operator user creation."""
    headers = await login_headers(client, verified_user_credentials)
    users_response = await client.get("/api/v1/server/users", headers=headers)
    assert users_response.status_code == status.HTTP_200_OK
    organization_id = users_response.json()["items"][0]["organization_id"]

    create_response = await client.post(
        "/api/v1/server/users",
        json={
            "email": "operator-invited@example.com",
            "organization_id": organization_id,
        },
        headers=headers,
    )
    assert create_response.status_code == status.HTTP_201_CREATED
    assert create_response.json()["is_active"] is True
    assert create_response.json()["email_verified"] is False
    raw_token = await notification_token(app, WorkflowTokenPurpose.INVITE)

    accept_response = await client.post(
        f"{AUTH_PATH}/invite/accept",
        json={"token": raw_token, "password": "0peratorInv1te!"},
    )
    async with browser_client_factory() as invited_browser:
        login_response = await login_browser(
            invited_browser,
            UserCredentials(
                email="operator-invited@example.com",
                password="0peratorInv1te!",  # noqa: S106
            ),
        )

    assert accept_response.status_code == status.HTTP_204_NO_CONTENT
    assert accept_response.content == b""
    assert login_response.status_code == status.HTTP_204_NO_CONTENT


@pytest.mark.asyncio
@pytest.mark.negative
async def test_invitation_cannot_reactivate_an_inactive_user(
    app: FastAPI,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Reject an older invitation after an administrator deactivates its user."""
    headers = await login_headers(client, verified_user_credentials)
    create_response = await client.post(
        "/api/v1/organization/users",
        json={"email": "deactivated-invite@example.com"},
        headers=headers,
    )
    assert create_response.status_code == status.HTTP_201_CREATED
    raw_token = await notification_token(app, WorkflowTokenPurpose.INVITE)
    async with app.state.core_session_factory() as db_session:
        await db_session.execute(
            update(UserDB)
            .where(
                UserDB.id
                == select(UserEmailDB.user_id)
                .where(
                    UserEmailDB.normalized_email == "deactivated-invite@example.com",
                    UserEmailDB.status == UserEmailStatus.CURRENT,
                )
                .scalar_subquery()
            )
            .values(is_active=False)
        )
        await db_session.commit()

    response = await client.post(
        f"{AUTH_PATH}/invite/accept",
        json={"token": raw_token, "password": "Inv1tedSecret2!"},
    )

    async with app.state.core_session_factory() as db_session:
        user = await db_session.scalar(
            select(UserDB)
            .options(active_email_loader())
            .join(UserEmailDB, UserEmailDB.user_id == UserDB.id)
            .where(
                UserEmailDB.normalized_email == "deactivated-invite@example.com",
                UserEmailDB.status == UserEmailStatus.CURRENT,
            )
        )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert user is not None
    assert user.is_active is False
    assert user.email_verified is False


@pytest.mark.asyncio
@pytest.mark.negative
async def test_notification_requests_do_not_reveal_unknown_accounts(
    client: httpx.AsyncClient,
) -> None:
    """Assert notification requests return the same empty success response."""
    verification = await client.post(
        f"{AUTH_PATH}/email/verify/request",
        json={"email": "unknown@example.com"},
    )
    reset = await client.post(
        f"{AUTH_PATH}/password/forgot",
        json={"email": "unknown@example.com"},
    )

    assert verification.status_code == status.HTTP_204_NO_CONTENT
    assert reset.status_code == status.HTTP_204_NO_CONTENT
    assert verification.content == b""
    assert reset.content == b""


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        "email/verify/confirm",
        "email/change/confirm",
        "password/reset",
        "invite/accept",
    ],
)
@pytest.mark.negative
async def test_confirmation_routes_reject_unknown_tokens(
    client: httpx.AsyncClient,
    path: str,
) -> None:
    """Assert token-consuming routes share the safe invalid-token response."""
    payload = {"token": "unknown-token-value"}
    if path not in {"email/verify/confirm", "email/change/confirm"}:
        payload["password"] = TEST_PASSWORD

    response = await client.post(f"{AUTH_PATH}/{path}", json=payload)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["code"] == "INVALID_WORKFLOW_TOKEN"
    assert response.json()["message"] == "Workflow token is invalid or expired."

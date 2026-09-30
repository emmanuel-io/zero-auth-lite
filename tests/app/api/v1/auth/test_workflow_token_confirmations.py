"""Unit tests for workflow token confirmation adapters."""

import pytest
from app.api.v1.auth.email_change import confirm_email_change
from app.api.v1.auth.email_verification import confirm_email_verification
from app.api.v1.auth.invitations import accept_invite
from app.api.v1.auth.password_recovery import reset_password
from app.api.v1.auth.schemas import (
    PasswordWorkflowTokenRequest,
    WorkflowTokenConfirmRequest,
)

from tests.app.api.v1.auth.helpers import (
    CHANGE_TOKEN,
    FakeWorkflowTokenConfirmationService,
    INVITE_TOKEN,
    NEW_PASSWORD,
    RESET_TOKEN,
    VERIFY_TOKEN,
)


pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_token_confirmation_adapters_call_service() -> None:
    """Delegate each token-consuming workflow to the domain service."""
    service = FakeWorkflowTokenConfirmationService()

    await confirm_email_verification(
        payload=WorkflowTokenConfirmRequest(token=VERIFY_TOKEN),
        workflow_token_confirmation_service=service,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
    )
    await confirm_email_change(
        payload=WorkflowTokenConfirmRequest(token=CHANGE_TOKEN),
        workflow_token_confirmation_service=service,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
    )
    await reset_password(
        payload=PasswordWorkflowTokenRequest(token=RESET_TOKEN, password=NEW_PASSWORD),
        workflow_token_confirmation_service=service,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
    )
    await accept_invite(
        payload=PasswordWorkflowTokenRequest(token=INVITE_TOKEN, password=NEW_PASSWORD),
        workflow_token_confirmation_service=service,  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]
    )

    assert service.registered_email_token == VERIFY_TOKEN
    assert service.email_change_token == CHANGE_TOKEN
    assert service.reset_token == RESET_TOKEN
    assert service.invite_token == INVITE_TOKEN

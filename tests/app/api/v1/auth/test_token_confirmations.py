"""Unit tests for authentication token confirmation adapters."""

import pytest
from app.api.v1.auth.email_change import confirm_email_change
from app.api.v1.auth.email_verification import confirm_email_verification
from app.api.v1.auth.invitations import accept_invite
from app.api.v1.auth.password_recovery import reset_password
from app.api.v1.auth.schemas import PasswordTokenRequest, TokenConfirmRequest

from tests.app.api.v1.auth.helpers import (
    CHANGE_TOKEN,
    FakeAuthTokenConfirmationService,
    INVITE_TOKEN,
    NEW_PASSWORD,
    RESET_TOKEN,
    VERIFY_TOKEN,
)


pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_token_confirmation_adapters_call_service() -> None:
    """Delegate each token-consuming workflow to the domain service."""
    service = FakeAuthTokenConfirmationService()

    await confirm_email_verification(
        payload=TokenConfirmRequest(token=VERIFY_TOKEN),
        auth_token_confirmation_service=service,  # type: ignore[arg-type]
    )
    await confirm_email_change(
        payload=TokenConfirmRequest(token=CHANGE_TOKEN),
        auth_token_confirmation_service=service,  # type: ignore[arg-type]
    )
    await reset_password(
        payload=PasswordTokenRequest(token=RESET_TOKEN, password=NEW_PASSWORD),
        auth_token_confirmation_service=service,  # type: ignore[arg-type]
    )
    await accept_invite(
        payload=PasswordTokenRequest(token=INVITE_TOKEN, password=NEW_PASSWORD),
        auth_token_confirmation_service=service,  # type: ignore[arg-type]
    )

    assert service.registered_email_token == VERIFY_TOKEN
    assert service.email_change_token == CHANGE_TOKEN
    assert service.reset_token == RESET_TOKEN
    assert service.invite_token == INVITE_TOKEN

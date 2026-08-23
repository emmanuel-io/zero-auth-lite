"""Unit tests for authentication notification request adapters."""

import pytest
from app.api.v1.auth.email_verification import request_email_verification
from app.api.v1.auth.password_recovery import forgot_password
from app.api.v1.auth.schemas import EmailRequest

from tests.app.api.v1.auth.helpers import FakeAuthNotificationRequestService


pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_notification_request_adapters_delegate_requests() -> None:
    """Delegate verification and password-reset intentions."""
    notification_requests = FakeAuthNotificationRequestService()

    await request_email_verification(
        payload=EmailRequest(email="user@example.com"),
        notification_requests=notification_requests,  # type: ignore[arg-type]
    )
    await forgot_password(
        payload=EmailRequest(email="user@example.com"),
        notification_requests=notification_requests,  # type: ignore[arg-type]
    )

    assert notification_requests.verification_emails == ["user@example.com"]
    assert notification_requests.password_reset_emails == ["user@example.com"]

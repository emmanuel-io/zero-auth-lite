"""Password-recovery HTTP routes."""

from fastapi import APIRouter, status

from app.api.v1.auth.responses import AUTH_TOKEN_CONFIRMATION_ERROR_RESPONSES
from app.api.v1.auth.schemas import EmailRequest, PasswordTokenRequest
from app.auth_tokens.dependencies import AuthTokenConfirmationServiceDep
from app.events.dependencies import AuthNotificationRequestServiceDep
from app.openapi_tags import AUTHENTICATION_V1_TAG


router = APIRouter(prefix="/password", tags=[AUTHENTICATION_V1_TAG])


@router.post("/forgot", status_code=status.HTTP_204_NO_CONTENT)
async def forgot_password(
    payload: EmailRequest,
    notification_requests: AuthNotificationRequestServiceDep,
) -> None:
    """Request a password reset without revealing account existence."""
    await notification_requests.request_password_reset(payload.email)


@router.post(
    "/reset",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=AUTH_TOKEN_CONFIRMATION_ERROR_RESPONSES,
)
async def reset_password(
    payload: PasswordTokenRequest,
    auth_token_confirmation_service: AuthTokenConfirmationServiceDep,
) -> None:
    """Reset a password and verify the email that received the token."""
    await auth_token_confirmation_service.reset_password(
        token=payload.token,
        password=payload.password,
    )

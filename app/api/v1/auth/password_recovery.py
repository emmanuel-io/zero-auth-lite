"""Password-recovery HTTP routes."""

from fastapi import APIRouter, status

from app.api.v1.auth.openapi_responses import (
    WORKFLOW_TOKEN_CONFIRMATION_ERROR_RESPONSES,
)
from app.api.v1.auth.schemas import EmailRequest, PasswordWorkflowTokenRequest
from app.notifications.dependencies import AuthNotificationRequestServiceDep
from app.openapi_tags import AUTHENTICATION_V1_TAG
from app.workflow_tokens.dependencies import WorkflowTokenConfirmationServiceDep


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
    responses=WORKFLOW_TOKEN_CONFIRMATION_ERROR_RESPONSES,
)
async def reset_password(
    payload: PasswordWorkflowTokenRequest,
    workflow_token_confirmation_service: WorkflowTokenConfirmationServiceDep,
) -> None:
    """Reset a password and verify the email that received the token."""
    await workflow_token_confirmation_service.reset_password(
        token=payload.token,
        password=payload.password,
    )

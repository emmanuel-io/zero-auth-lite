"""Self-registration email-verification HTTP routes."""

from fastapi import APIRouter, status

from app.api.v1.auth.openapi_responses import (
    WORKFLOW_TOKEN_CONFIRMATION_ERROR_RESPONSES,
)
from app.api.v1.auth.schemas import EmailRequest, WorkflowTokenConfirmRequest
from app.notifications.dependencies import AuthNotificationRequestServiceDep
from app.openapi_tags import AUTHENTICATION_V1_TAG
from app.workflow_tokens.dependencies import WorkflowTokenConfirmationServiceDep


request_router = APIRouter(prefix="/email/verify", tags=[AUTHENTICATION_V1_TAG])
confirmation_router = APIRouter(prefix="/email/verify", tags=[AUTHENTICATION_V1_TAG])


@request_router.post("/request", status_code=status.HTTP_204_NO_CONTENT)
async def request_email_verification(
    payload: EmailRequest,
    notification_requests: AuthNotificationRequestServiceDep,
) -> None:
    """Request a new email verification link."""
    await notification_requests.request_account_verification(payload.email)


@confirmation_router.post(
    "/confirm",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=WORKFLOW_TOKEN_CONFIRMATION_ERROR_RESPONSES,
)
async def confirm_email_verification(
    payload: WorkflowTokenConfirmRequest,
    workflow_token_confirmation_service: WorkflowTokenConfirmationServiceDep,
) -> None:
    """Confirm an email verification token."""
    await workflow_token_confirmation_service.confirm_registered_email(payload.token)

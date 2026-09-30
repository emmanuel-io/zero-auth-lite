"""Email-address change confirmation HTTP routes."""

from fastapi import APIRouter, status

from app.api.v1.auth.openapi_responses import (
    WORKFLOW_TOKEN_CONFIRMATION_ERROR_RESPONSES,
)
from app.api.v1.auth.schemas import WorkflowTokenConfirmRequest
from app.openapi_tags import AUTHENTICATION_V1_TAG
from app.workflow_tokens.dependencies import WorkflowTokenConfirmationServiceDep


router = APIRouter(prefix="/email/change", tags=[AUTHENTICATION_V1_TAG])


@router.post(
    "/confirm",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=WORKFLOW_TOKEN_CONFIRMATION_ERROR_RESPONSES,
)
async def confirm_email_change(
    payload: WorkflowTokenConfirmRequest,
    workflow_token_confirmation_service: WorkflowTokenConfirmationServiceDep,
) -> None:
    """Confirm a pending email-address change token."""
    await workflow_token_confirmation_service.confirm_email_change(payload.token)

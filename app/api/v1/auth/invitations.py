"""User-invitation acceptance HTTP routes."""

from fastapi import APIRouter, status

from app.api.v1.auth.openapi_responses import (
    WORKFLOW_TOKEN_CONFIRMATION_ERROR_RESPONSES,
)
from app.api.v1.auth.schemas import PasswordWorkflowTokenRequest
from app.openapi_tags import AUTHENTICATION_V1_TAG
from app.workflow_tokens.dependencies import WorkflowTokenConfirmationServiceDep


router = APIRouter(prefix="/invite", tags=[AUTHENTICATION_V1_TAG])


@router.post(
    "/accept",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=WORKFLOW_TOKEN_CONFIRMATION_ERROR_RESPONSES,
)
async def accept_invite(
    payload: PasswordWorkflowTokenRequest,
    workflow_token_confirmation_service: WorkflowTokenConfirmationServiceDep,
) -> None:
    """Accept an application invite by setting the first password."""
    await workflow_token_confirmation_service.accept_invite(
        token=payload.token,
        password=payload.password,
    )

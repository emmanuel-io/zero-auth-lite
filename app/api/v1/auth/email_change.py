"""Email-address change confirmation HTTP routes."""

from fastapi import APIRouter, status

from app.api.v1.auth.responses import AUTH_TOKEN_CONFIRMATION_ERROR_RESPONSES
from app.api.v1.auth.schemas import TokenConfirmRequest
from app.auth_tokens.dependencies import AuthTokenConfirmationServiceDep
from app.openapi_tags import AUTHENTICATION_V1_TAG


router = APIRouter(prefix="/email/change", tags=[AUTHENTICATION_V1_TAG])


@router.post(
    "/confirm",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=AUTH_TOKEN_CONFIRMATION_ERROR_RESPONSES,
)
async def confirm_email_change(
    payload: TokenConfirmRequest,
    auth_token_confirmation_service: AuthTokenConfirmationServiceDep,
) -> None:
    """Confirm a pending email-address change token."""
    await auth_token_confirmation_service.confirm_email_change(payload.token)

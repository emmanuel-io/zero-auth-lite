"""User-invitation acceptance HTTP routes."""

from fastapi import APIRouter, status

from app.api.v1.auth.responses import AUTH_TOKEN_CONFIRMATION_ERROR_RESPONSES
from app.api.v1.auth.schemas import PasswordTokenRequest
from app.auth_tokens.dependencies import AuthTokenConfirmationServiceDep
from app.openapi_tags import AUTHENTICATION_V1_TAG


router = APIRouter(prefix="/invite", tags=[AUTHENTICATION_V1_TAG])


@router.post(
    "/accept",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=AUTH_TOKEN_CONFIRMATION_ERROR_RESPONSES,
)
async def accept_invite(
    payload: PasswordTokenRequest,
    auth_token_confirmation_service: AuthTokenConfirmationServiceDep,
) -> None:
    """Accept an application invite by setting the first password."""
    await auth_token_confirmation_service.accept_invite(
        token=payload.token,
        password=payload.password,
    )

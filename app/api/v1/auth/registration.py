"""Organization and initial-user registration HTTP routes."""

from fastapi import APIRouter, status

from app.api.v1.auth.openapi_responses import REGISTRATION_ERROR_RESPONSES
from app.api.v1.auth.schemas import (
    RegisterRequest,
    RegistrationResponse,
)
from app.identity.dependencies import RegistrationServiceDep
from app.identity.dtos import RegistrationCreateDTO
from app.openapi_tags import AUTHENTICATION_V1_TAG


router = APIRouter(tags=[AUTHENTICATION_V1_TAG])


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    responses=REGISTRATION_ERROR_RESPONSES,
)
async def register_user(
    payload: RegisterRequest,
    registration_service: RegistrationServiceDep,
) -> RegistrationResponse:
    """Register an organization and its initial user through the identity lifecycle."""
    registration = RegistrationCreateDTO(
        email=payload.email,
        password=payload.password,
        organization_name=payload.organization_name,
        first_name=payload.first_name,
        last_name=payload.last_name,
    )

    result = await registration_service.register(
        registration=registration,
    )
    return RegistrationResponse(
        public_id=result.public_id,
        organization_public_id=result.organization_public_id,
        email=result.email,
        first_name=result.first_name,
        last_name=result.last_name,
        is_active=result.is_active,
        role=result.role,
        email_verified=result.email_verified,
    )

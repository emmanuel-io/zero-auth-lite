"""Organization and initial-user registration HTTP routes."""

from fastapi import APIRouter, status

from app.api.v1.auth.responses import REGISTRATION_ERROR_RESPONSES
from app.api.v1.auth.schemas import (
    RegisterRequest,
    RegistrationResponse,
)
from app.db.dependencies import DbSessionDep
from app.events.dependencies import EventPublisherDep
from app.identity.dtos import RegistrationCreateDTO
from app.identity.registration import RegistrationService
from app.openapi_tags import AUTHENTICATION_V1_TAG
from app.password.dependencies import PasswordHasherDep


router = APIRouter(tags=[AUTHENTICATION_V1_TAG])


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    responses=REGISTRATION_ERROR_RESPONSES,
)
async def register_user(
    payload: RegisterRequest,
    db_session: DbSessionDep,
    event_publisher: EventPublisherDep,
    password_hasher: PasswordHasherDep,
) -> RegistrationResponse:
    """Register an organization and its initial user through the identity lifecycle."""
    service = RegistrationService(
        db_session=db_session,
        event_publisher=event_publisher,
        password_hasher=password_hasher,
    )
    registration = RegistrationCreateDTO(
        email=payload.email,
        password=payload.password,
        organization_name=payload.organization_name,
        first_name=payload.first_name,
        last_name=payload.last_name,
    )

    result = await service.register(
        registration=registration,
    )
    return RegistrationResponse(
        id=result.id,
        organization_id=result.organization_id,
        email=result.email,
        first_name=result.first_name,
        last_name=result.last_name,
        is_active=result.is_active,
        role=result.role,
        email_verified=result.email_verified,
    )

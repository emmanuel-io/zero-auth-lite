"""FastAPI dependencies for authorization-code OAuth2 services."""

from typing import Annotated

from fastapi import Depends

from app.db.dependencies import DbSessionDep
from app.oauth2.authorization.request import AuthorizationRequestService
from app.settings.dependencies import OAuth2SettingsDep


def get_authorization_request_service(
    settings: OAuth2SettingsDep,
    db_session: DbSessionDep,
) -> AuthorizationRequestService:
    """Provide the authorization-request service."""
    return AuthorizationRequestService(
        settings=settings,
        db_session=db_session,
    )


AuthorizationRequestServiceDep = Annotated[
    AuthorizationRequestService, Depends(get_authorization_request_service)
]

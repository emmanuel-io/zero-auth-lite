"""FastAPI dependency for OAuth2 bearer-principal resolution."""

from typing import Annotated

from fastapi import Depends

from app.db.dependencies import DbSessionDep
from app.oauth2.principal import OAuth2BearerPrincipalService
from app.settings.dependencies import OAuth2SettingsDep


def get_oauth2_bearer_principal_service(
    db_session: DbSessionDep,
    settings: OAuth2SettingsDep,
) -> OAuth2BearerPrincipalService:
    """Provide the OAuth2 bearer-principal service."""
    return OAuth2BearerPrincipalService(db_session=db_session, settings=settings)


OAuth2BearerPrincipalServiceDep = Annotated[
    OAuth2BearerPrincipalService,
    Depends(get_oauth2_bearer_principal_service),
]

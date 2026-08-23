"""FastAPI dependencies for token lifecycle OAuth2 services."""

from typing import Annotated

from fastapi import Depends

from app.db.dependencies import DbSessionDep
from app.oauth2.tokens.introspection import TokenIntrospectionService
from app.settings.dependencies import OAuth2SettingsDep


def get_token_introspection_service(
    settings: OAuth2SettingsDep,
    db_session: DbSessionDep,
) -> TokenIntrospectionService:
    """Provide the token-introspection service."""
    return TokenIntrospectionService(
        db_session=db_session,
        settings=settings,
    )


TokenIntrospectionServiceDep = Annotated[
    TokenIntrospectionService, Depends(get_token_introspection_service)
]

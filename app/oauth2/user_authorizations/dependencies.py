"""FastAPI dependencies for current-user OAuth2 authorizations."""

from typing import Annotated

from fastapi import Depends

from app.db.dependencies import DbSessionDep
from app.oauth2.user_authorizations.service import OAuth2AuthorizationService


def get_oauth2_authorization_service(
    db_session: DbSessionDep,
) -> OAuth2AuthorizationService:
    """Build the current-user OAuth2 authorization service."""
    return OAuth2AuthorizationService(
        db_session=db_session,
    )


OAuth2AuthorizationServiceDep = Annotated[
    OAuth2AuthorizationService,
    Depends(get_oauth2_authorization_service),
]

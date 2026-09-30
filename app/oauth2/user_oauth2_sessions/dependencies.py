"""FastAPI dependencies for current-user OAuth2 sessions."""

from typing import Annotated

from fastapi import Depends

from app.db.dependencies import DbSessionDep
from app.oauth2.user_oauth2_sessions.service import UserOAuth2SessionService


def get_user_oauth2_session_service(
    db_session: DbSessionDep,
) -> UserOAuth2SessionService:
    """Build the current-user OAuth2 session service."""
    return UserOAuth2SessionService(
        db_session=db_session,
    )


UserOAuth2SessionServiceDep = Annotated[
    UserOAuth2SessionService,
    Depends(get_user_oauth2_session_service),
]

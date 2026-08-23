"""FastAPI dependency for organization-scoped OAuth2 session administration."""

from typing import Annotated

from fastapi import Depends

from app.db.dependencies import DbSessionDep
from app.oauth2.organization_oauth2_sessions import OrganizationOAuth2SessionService


def get_organization_oauth2_session_service(
    db_session: DbSessionDep,
) -> OrganizationOAuth2SessionService:
    """Build the organization-scoped OAuth2 session service."""
    return OrganizationOAuth2SessionService(db_session=db_session)


OrganizationOAuth2SessionServiceDep = Annotated[
    OrganizationOAuth2SessionService,
    Depends(get_organization_oauth2_session_service),
]

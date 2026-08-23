"""Dependency wiring for organization-scoped security-session authorization."""

from typing import Annotated

from fastapi import Depends

from app.db.dependencies import DbSessionDep
from app.security.organization_security_session_authorization import (
    OrganizationSecuritySessionAuthorizationService,
)


def get_organization_security_session_authorization_service(
    db_session: DbSessionDep,
) -> OrganizationSecuritySessionAuthorizationService:
    """Build explicit-organization security-session authorization."""
    return OrganizationSecuritySessionAuthorizationService(db_session)


OrganizationSecuritySessionAuthorizationServiceDep = Annotated[
    OrganizationSecuritySessionAuthorizationService,
    Depends(get_organization_security_session_authorization_service),
]

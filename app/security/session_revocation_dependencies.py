"""Dependency wiring for SQL-first security-session revocation."""

from typing import Annotated

from fastapi import Depends

from app.db.dependencies import DbSessionDep
from app.security.session_revocation import SecuritySessionRevocationService


def get_security_session_revocation_service(
    db_session: DbSessionDep,
) -> SecuritySessionRevocationService:
    """Build the transactional SQL revocation boundary."""
    return SecuritySessionRevocationService(db_session=db_session)


SecuritySessionRevocationDep = Annotated[
    SecuritySessionRevocationService,
    Depends(get_security_session_revocation_service),
]

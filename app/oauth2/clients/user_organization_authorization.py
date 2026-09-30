"""User-organization authorization for global OAuth2 clients."""

from fastapi import status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors.base import AppError
from app.db.models.oauth2_client import (
    OAuth2ClientDB,
    OAuth2ClientUserOrganizationDB,
)
from app.oauth2.clients.access import (
    OAuth2ClientUserOrganizationAccess,
    organization_assignment_count_is_valid,
)
from app.oauth2.clients.dtos import OAuth2ClientReadDTO


class OAuth2ClientNotAllowedForUserOrganizationError(AppError):
    """Raised when a user-backed grant crosses a client's organization policy."""

    code = "OAUTH2_CLIENT_NOT_ALLOWED_FOR_USER_ORGANIZATION"
    message = "This OAuth2 client is not available for the user's organization."
    status = status.HTTP_403_FORBIDDEN


async def ensure_client_allows_user_organization(
    *,
    client: OAuth2ClientReadDTO,
    organization_id: int,
    db_session: AsyncSession,
) -> None:
    """Require a client to allow the internal organization for a user-backed grant.

    Persisted assignment cardinality is checked before applying the policy so
    inconsistent direct database changes fail closed.
    """
    access = client.user_organization_access
    client_internal_id = (
        select(OAuth2ClientDB.id)
        .where(OAuth2ClientDB.client_id == client.client_id)
        .scalar_subquery()
    )
    assignment_count = await db_session.scalar(
        select(func.count())
        .select_from(OAuth2ClientUserOrganizationDB)
        .where(OAuth2ClientUserOrganizationDB.client_id == client_internal_id)
    )
    if not organization_assignment_count_is_valid(
        mode=access, assignment_count=assignment_count or 0
    ):
        raise OAuth2ClientNotAllowedForUserOrganizationError
    if access == OAuth2ClientUserOrganizationAccess.UNRESTRICTED:
        return
    allowed = await db_session.scalar(
        select(OAuth2ClientUserOrganizationDB.client_id)
        .where(
            OAuth2ClientUserOrganizationDB.client_id == client_internal_id,
            OAuth2ClientUserOrganizationDB.organization_id == organization_id,
        )
        .limit(1)
    )
    if allowed is None:
        raise OAuth2ClientNotAllowedForUserOrganizationError

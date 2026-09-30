"""Authorization for explicit-organization security-session revocation."""

from dataclasses import dataclass
from uuid import UUID

from fastapi import status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors.base import AppError
from app.core.errors.common import ForbiddenOperationError, ObjectNotFoundError
from app.db.models.oauth2_client import (
    OAuth2ClientDB,
    OAuth2ClientMachineOrganizationDB,
)
from app.db.models.organization import OrganizationDB
from app.oauth2.clients.access import (
    OAuth2ClientMachineOrganizationAccess,
    organization_assignment_count_is_valid,
)
from app.oauth2.clients.dtos import OAuth2ClientReadDTO
from app.oauth2.grants.types import OAuth2GrantType
from app.security.permissions import Permission
from app.security.principals import (
    AuthenticatedPrincipalContext,
    AuthenticationMechanism,
    OAuth2ClientPrincipalContext,
    UserPrincipalContext,
)


class MachineClientOrganizationAccessDeniedError(AppError):
    """Raised when a machine client cannot access a target organization."""

    code = "MACHINE_CLIENT_ORGANIZATION_ACCESS_DENIED"
    message = "The machine client is not authorized to access this organization."
    status = status.HTTP_403_FORBIDDEN


@dataclass(frozen=True, slots=True)
class AuthorizedOrganizationSecuritySessionRevocation:
    """Authorized target organization paired with its principal."""

    organization_id: int
    principal: AuthenticatedPrincipalContext


class OrganizationSecuritySessionAuthorizationService:
    """Authorize an operator or machine client for one organization target."""

    def __init__(self, db_session: AsyncSession) -> None:
        """Bind authorization reads to the request transaction."""
        self.db_session = db_session

    @staticmethod
    def _require_operator(principal: UserPrincipalContext) -> None:
        """Require operator authority and the sessions-write permission."""
        has_permission = Permission.SESSIONS_WRITE in principal.permissions
        if principal.authentication_mechanism is AuthenticationMechanism.OAUTH2_BEARER:
            has_permission = (
                has_permission and Permission.SESSIONS_WRITE.value in principal.scopes
            )
        if not principal.is_operator or not has_permission:
            raise ForbiddenOperationError

    async def _require_machine_client(
        self, principal: OAuth2ClientPrincipalContext
    ) -> OAuth2ClientReadDTO:
        """Reload and validate the machine client's current access policy."""
        if Permission.SESSIONS_WRITE.value not in principal.scopes:
            raise MachineClientOrganizationAccessDeniedError
        row = await self.db_session.scalar(
            select(OAuth2ClientDB).where(
                OAuth2ClientDB.client_id == principal.client_id
            )
        )
        if row is None:
            raise MachineClientOrganizationAccessDeniedError
        client = OAuth2ClientReadDTO.model_validate(row)
        if (
            not client.is_active
            or OAuth2GrantType.CLIENT_CREDENTIALS.value not in client.grant_types
            or client.machine_organization_access
            == OAuth2ClientMachineOrganizationAccess.NONE
        ):
            raise MachineClientOrganizationAccessDeniedError
        assignment_count = await self.db_session.scalar(
            select(func.count())
            .select_from(OAuth2ClientMachineOrganizationDB)
            .where(OAuth2ClientMachineOrganizationDB.client_id == row.id)
        )
        if not organization_assignment_count_is_valid(
            mode=client.machine_organization_access,
            assignment_count=assignment_count or 0,
        ):
            raise MachineClientOrganizationAccessDeniedError
        return client

    async def authorize(
        self,
        *,
        organization_public_id: UUID,
        principal: AuthenticatedPrincipalContext,
    ) -> AuthorizedOrganizationSecuritySessionRevocation:
        """Resolve and authorize one explicit organization target."""
        if isinstance(principal, OAuth2ClientPrincipalContext):
            client = await self._require_machine_client(principal)
        else:
            client = None
            self._require_operator(principal)

        organization = await self.db_session.scalar(
            select(OrganizationDB).where(
                OrganizationDB.public_id == organization_public_id
            )
        )
        if organization is None:
            raise ObjectNotFoundError

        if client is not None and client.machine_organization_access in {
            OAuth2ClientMachineOrganizationAccess.SINGLE,
            OAuth2ClientMachineOrganizationAccess.SELECTED,
        }:
            client_internal_id = (
                select(OAuth2ClientDB.id)
                .where(OAuth2ClientDB.client_id == client.client_id)
                .scalar_subquery()
            )
            allowed = await self.db_session.scalar(
                select(OAuth2ClientMachineOrganizationDB.client_id)
                .where(
                    OAuth2ClientMachineOrganizationDB.client_id == client_internal_id,
                    OAuth2ClientMachineOrganizationDB.organization_id
                    == organization.id,
                )
                .limit(1)
            )
            if allowed is None:
                raise ObjectNotFoundError
        return AuthorizedOrganizationSecuritySessionRevocation(
            organization_id=organization.id,
            principal=principal,
        )

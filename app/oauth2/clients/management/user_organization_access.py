"""User-backed organization assignments for OAuth2 clients."""

from logging import getLogger

from app.identity.public_ids import format_organization_id
from app.oauth2.clients.access import OAuth2ClientUserOrganizationAccess
from app.oauth2.clients.dtos import (
    OAuth2ClientOrganizationDTO,
    OAuth2ClientUserOrganizationsDTO,
)
from app.oauth2.clients.management.authorization import require_operator
from app.oauth2.clients.management.errors import (
    OAuth2ClientAdminNotFoundError,
    OAuth2ClientOrganizationAccessConflictError,
)
from app.oauth2.clients.management.support import OAuth2ClientManagementSupport
from app.security.dtos import UserPrincipalContext


logger = getLogger(__name__)
ERR_SINGLE_ORGANIZATION_LIMIT = "OAUTH2_CLIENT_SINGLE_ORGANIZATION_LIMIT"
ERR_USER_ORGANIZATION_ACCESS_INVALID = "OAUTH2_CLIENT_USER_ORGANIZATION_ACCESS_INVALID"


class OAuth2ClientUserOrganizationAccessService(OAuth2ClientManagementSupport):
    """Manage user-backed organization assignments for OAuth2 clients."""

    async def list_user_organizations(
        self, *, client_id: str, operator_ctx: UserPrincipalContext
    ) -> OAuth2ClientUserOrganizationsDTO:
        """List explicit user-organization assignments for one global client."""
        require_operator(operator_ctx)
        client = await self._read_client(client_id)
        if client is None:
            raise OAuth2ClientAdminNotFoundError
        organizations = await self._list_user_organizations(client_id=client_id)
        return OAuth2ClientUserOrganizationsDTO(
            user_organization_access=client.user_organization_access,
            organizations=[
                OAuth2ClientOrganizationDTO(
                    organization_id=format_organization_id(organization.public_id),
                    name=organization.name,
                )
                for organization in organizations
            ],
        )

    async def replace_user_organizations(
        self,
        *,
        client_id: str,
        organization_ids: list[str],
        operator_ctx: UserPrincipalContext,
    ) -> OAuth2ClientUserOrganizationsDTO:
        """Validate and atomically replace one client's user organizations."""
        require_operator(operator_ctx)
        client = await self._read_client(client_id)
        if client is None:
            raise OAuth2ClientAdminNotFoundError
        if (
            client.user_organization_access
            == OAuth2ClientUserOrganizationAccess.UNRESTRICTED
            and organization_ids
        ):
            raise OAuth2ClientOrganizationAccessConflictError(
                ERR_USER_ORGANIZATION_ACCESS_INVALID
            )
        if (
            client.user_organization_access == OAuth2ClientUserOrganizationAccess.SINGLE
            and len(organization_ids) != 1
        ):
            raise OAuth2ClientOrganizationAccessConflictError(
                ERR_SINGLE_ORGANIZATION_LIMIT
            )

        previous = await self._list_user_organizations(client_id=client_id)
        resolved = await self._resolve_organizations(organization_ids)
        await self._replace_user_organizations(
            client_id=client_id,
            organization_ids=[organization.id for organization in resolved],
        )
        previous_ids = {organization.id for organization in previous}
        current_ids = {organization.id for organization in resolved}
        if previous_ids - current_ids:
            revoked_sessions = await self.session_revocation.persist(
                client_id=client_id
            )
            logger.info(
                (
                    "OAuth2 client user-organization policy narrowed client_id=%s "
                    "revoked_sessions=%s"
                ),
                client_id,
                revoked_sessions,
            )
        await self.db_session.flush()
        return await self.list_user_organizations(
            client_id=client_id, operator_ctx=operator_ctx
        )

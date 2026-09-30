"""User-backed organization assignments for OAuth2 clients."""

from logging import getLogger
from uuid import UUID

from app.oauth2.clients.dtos import (
    OAuth2ClientOrganizationDTO,
    OAuth2ClientPersistenceUpdateDTO,
    OAuth2ClientUserOrganizationsDTO,
    OAuth2ClientUserOrganizationUpdateDTO,
)
from app.oauth2.clients.management.authorization import require_operator
from app.oauth2.clients.management.errors import OAuth2ClientManagementNotFoundError
from app.oauth2.clients.management.support import OAuth2ClientManagementSupport
from app.oauth2.clients.management.user_organization_policy import (
    user_organization_policy_narrowed,
    validate_user_organization_policy,
)
from app.security.principals import UserPrincipalContext


logger = getLogger(__name__)


class OAuth2ClientUserOrganizationAccessService(OAuth2ClientManagementSupport):
    """Manage user-backed organization assignments for OAuth2 clients."""

    async def list_user_organizations(
        self, *, client_id: UUID, operator_ctx: UserPrincipalContext
    ) -> OAuth2ClientUserOrganizationsDTO:
        """List explicit user-organization assignments for one global client."""
        require_operator(operator_ctx)
        client = await self._read_client(client_id)
        if client is None:
            raise OAuth2ClientManagementNotFoundError
        organizations = await self._list_user_organizations(client_id=client_id)
        organization_ids = [organization.public_id for organization in organizations]
        validate_user_organization_policy(
            mode=client.user_organization_access,
            organization_ids=organization_ids,
        )
        return OAuth2ClientUserOrganizationsDTO(
            user_organization_access=client.user_organization_access,
            organizations=[
                OAuth2ClientOrganizationDTO(
                    organization_id=organization.public_id,
                    name=organization.name,
                )
                for organization in organizations
            ],
        )

    async def replace_user_organizations(
        self,
        *,
        client_id: UUID,
        dto: OAuth2ClientUserOrganizationUpdateDTO,
        operator_ctx: UserPrincipalContext,
    ) -> OAuth2ClientUserOrganizationsDTO:
        """Validate and atomically replace one client's user organizations."""
        require_operator(operator_ctx)
        client = await self._read_client(client_id)
        if client is None:
            raise OAuth2ClientManagementNotFoundError
        validate_user_organization_policy(
            mode=dto.user_organization_access,
            organization_ids=dto.organization_ids,
        )

        previous = await self._list_user_organizations(client_id=client_id)
        resolved = await self._resolve_organizations(dto.organization_ids)
        await self._replace_user_organizations(
            client_id=client_id,
            organization_ids=[organization.id for organization in resolved],
        )
        await self._update_client(
            client_id=client_id,
            data=OAuth2ClientPersistenceUpdateDTO(
                client_secret=client.client_secret,
                name=client.name,
                grant_types=client.grant_types,
                scopes=client.scopes,
                redirect_uris=client.redirect_uris,
                is_confidential=client.is_confidential,
                requires_consent=client.requires_consent,
                is_active=client.is_active,
                user_organization_access=dto.user_organization_access,
                machine_organization_access=client.machine_organization_access,
            ),
        )
        previous_ids = {organization.id for organization in previous}
        current_ids = {organization.id for organization in resolved}
        if user_organization_policy_narrowed(
            previous_mode=client.user_organization_access,
            current_mode=dto.user_organization_access,
            previous_organization_ids=previous_ids,
            current_organization_ids=current_ids,
        ):
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

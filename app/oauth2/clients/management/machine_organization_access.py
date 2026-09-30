"""Machine organization-access policy for OAuth2 clients."""

from logging import getLogger
from uuid import UUID

from app.oauth2.clients.access import (
    OAuth2ClientMachineOrganizationAccess,
    organization_assignment_count_is_valid,
)
from app.oauth2.clients.dtos import (
    OAuth2ClientMachineOrganizationsDTO,
    OAuth2ClientMachineOrganizationUpdateDTO,
    OAuth2ClientPersistenceUpdateDTO,
)
from app.oauth2.clients.management.authorization import require_operator
from app.oauth2.clients.management.errors import (
    OAuth2ClientManagementErrorReason,
    OAuth2ClientManagementNotFoundError,
    OAuth2ClientOrganizationAccessConflictError,
)
from app.oauth2.clients.management.support import OAuth2ClientManagementSupport
from app.security.principals import UserPrincipalContext


logger = getLogger(__name__)


def validate_machine_organization_policy(
    *, mode: OAuth2ClientMachineOrganizationAccess, organization_count: int
) -> None:
    """Require assignment cardinality consistent with a machine access mode."""
    if organization_assignment_count_is_valid(
        mode=mode, assignment_count=organization_count
    ):
        return
    if mode in {
        OAuth2ClientMachineOrganizationAccess.NONE,
        OAuth2ClientMachineOrganizationAccess.UNRESTRICTED,
    }:
        reason = OAuth2ClientManagementErrorReason.MACHINE_ORGANIZATION_ACCESS_INVALID
    elif mode == OAuth2ClientMachineOrganizationAccess.SINGLE:
        reason = OAuth2ClientManagementErrorReason.MACHINE_SINGLE_ORGANIZATION_LIMIT
    else:
        reason = OAuth2ClientManagementErrorReason.MACHINE_ORGANIZATION_REQUIRED
    raise OAuth2ClientOrganizationAccessConflictError(reason)


class OAuth2ClientMachineOrganizationAccessService(OAuth2ClientManagementSupport):
    """Manage machine organization access for OAuth2 clients."""

    @staticmethod
    def _policy_narrowed(
        *,
        previous_mode: OAuth2ClientMachineOrganizationAccess,
        current_mode: OAuth2ClientMachineOrganizationAccess,
        previous_organization_ids: set[int],
        current_organization_ids: set[int],
    ) -> bool:
        """Return whether a machine policy replacement removes authority."""
        if previous_mode == OAuth2ClientMachineOrganizationAccess.NONE:
            return False
        if current_mode == OAuth2ClientMachineOrganizationAccess.NONE:
            return True
        if previous_mode == OAuth2ClientMachineOrganizationAccess.UNRESTRICTED:
            return current_mode != OAuth2ClientMachineOrganizationAccess.UNRESTRICTED
        if current_mode == OAuth2ClientMachineOrganizationAccess.UNRESTRICTED:
            return False
        return bool(previous_organization_ids - current_organization_ids)

    async def list_machine_organizations(
        self, *, client_id: UUID, operator_ctx: UserPrincipalContext
    ) -> OAuth2ClientMachineOrganizationsDTO:
        """List the current machine policy and explicit assignments."""
        require_operator(operator_ctx)
        client = await self._read_client(client_id)
        if client is None:
            raise OAuth2ClientManagementNotFoundError
        organizations = await self._list_machine_organizations(client_id=client_id)
        validate_machine_organization_policy(
            mode=client.machine_organization_access,
            organization_count=len(organizations),
        )
        return OAuth2ClientMachineOrganizationsDTO(
            client_id=client.client_id,
            machine_organization_access=client.machine_organization_access,
            organization_ids=[organization.public_id for organization in organizations],
        )

    async def replace_machine_organization_access(
        self,
        *,
        client_id: UUID,
        dto: OAuth2ClientMachineOrganizationUpdateDTO,
        operator_ctx: UserPrincipalContext,
    ) -> OAuth2ClientMachineOrganizationsDTO:
        """Atomically replace a machine access mode and assignment set."""
        require_operator(operator_ctx)
        client = await self._read_client(client_id)
        if client is None:
            raise OAuth2ClientManagementNotFoundError
        mode = dto.machine_organization_access
        if (
            "client_credentials" not in client.grant_types
            and mode != OAuth2ClientMachineOrganizationAccess.NONE
        ):
            raise OAuth2ClientOrganizationAccessConflictError(
                OAuth2ClientManagementErrorReason.MACHINE_ACCESS_REQUIRES_CLIENT_CREDENTIALS
            )

        previous = await self._list_machine_organizations(client_id=client_id)
        target = (
            previous
            if dto.organization_ids is None
            else await self._resolve_organizations(dto.organization_ids)
        )
        if mode in {
            OAuth2ClientMachineOrganizationAccess.NONE,
            OAuth2ClientMachineOrganizationAccess.UNRESTRICTED,
        }:
            if dto.organization_ids not in (None, []):
                raise OAuth2ClientOrganizationAccessConflictError(
                    OAuth2ClientManagementErrorReason.MACHINE_ORGANIZATION_ACCESS_INVALID
                )
            target = []
        validate_machine_organization_policy(mode=mode, organization_count=len(target))

        await self._replace_machine_organizations(
            client_id=client_id,
            organization_ids=[organization.id for organization in target],
        )
        updated = await self._update_client(
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
                user_organization_access=client.user_organization_access,
                machine_organization_access=mode,
            ),
        )
        if self._policy_narrowed(
            previous_mode=client.machine_organization_access,
            current_mode=mode,
            previous_organization_ids={organization.id for organization in previous},
            current_organization_ids={organization.id for organization in target},
        ):
            revoked_sessions = await self.session_revocation.persist(
                client_id=client_id
            )
            logger.info(
                (
                    "OAuth2 client machine policy narrowed client_id=%s "
                    "revoked_sessions=%s"
                ),
                client_id,
                revoked_sessions,
            )
        await self.db_session.flush()
        return OAuth2ClientMachineOrganizationsDTO(
            client_id=updated.client_id,
            machine_organization_access=updated.machine_organization_access,
            organization_ids=[organization.public_id for organization in target],
        )

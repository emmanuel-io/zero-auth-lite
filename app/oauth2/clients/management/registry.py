"""Registry administration for global OAuth2 clients."""

from logging import getLogger

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.oauth2_client import (
    OAuth2ClientDB,
    OAuth2ClientUserOrganizationDB,
)
from app.identity.public_ids import format_user_id
from app.oauth2.clients.access import (
    OAuth2ClientMachineOrganizationAccess,
    OAuth2ClientUserOrganizationAccess,
)
from app.oauth2.clients.dtos import (
    OAuth2ClientPersistenceUpdateDTO,
    OAuth2ClientReadDTO,
    OAuth2ClientRegistryReplaceDTO,
)
from app.oauth2.clients.management.authorization import require_operator
from app.oauth2.clients.management.errors import (
    InvalidOAuth2ClientPayloadError,
    OAuth2ClientAdminNotFoundError,
    OAuth2ClientOrganizationAccessConflictError,
)
from app.oauth2.clients.management.policy import (
    ERR_CLIENT_SECRET_ROTATION_REQUIRED,
    OAuth2ClientPolicy,
)
from app.oauth2.clients.management.support import OAuth2ClientManagementSupport
from app.security.dtos import UserPrincipalContext


logger = getLogger(__name__)
ERR_CLIENT_TYPE_IMMUTABLE = "client_type_is_immutable"
ERR_USER_ORGANIZATION_ACCESS_INVALID = "OAUTH2_CLIENT_USER_ORGANIZATION_ACCESS_INVALID"
ERR_MACHINE_REQUIRES_CLIENT_CREDENTIALS = (
    "OAUTH2_CLIENT_MACHINE_ACCESS_REQUIRES_CLIENT_CREDENTIALS"
)


class OAuth2ClientRegistryService(OAuth2ClientManagementSupport):
    """Read, replace, and delete global OAuth2 client registrations."""

    def __init__(self, *, db_session: AsyncSession, policy: OAuth2ClientPolicy) -> None:
        """Initialize registry persistence and validation policy."""
        super().__init__(db_session=db_session)
        self.policy = policy

    @staticmethod
    def _user_policy_narrowed(
        *,
        previous: OAuth2ClientUserOrganizationAccess,
        current: OAuth2ClientUserOrganizationAccess,
    ) -> bool:
        """Return whether a user-organization access mode removes authority."""
        if previous == current:
            return False
        if previous == OAuth2ClientUserOrganizationAccess.UNRESTRICTED:
            return True
        return current == OAuth2ClientUserOrganizationAccess.SINGLE

    async def _revoke_if_client_capabilities_narrowed(
        self, *, existing: OAuth2ClientReadDTO, updated: OAuth2ClientReadDTO
    ) -> None:
        """Revoke issued families when a client replacement removes capabilities."""
        narrowed = (
            bool(set(existing.scopes) - set(updated.scopes))
            or bool(set(existing.grant_types) - set(updated.grant_types))
            or (existing.is_active and not updated.is_active)
            or self._user_policy_narrowed(
                previous=existing.user_organization_access,
                current=updated.user_organization_access,
            )
        )
        if not narrowed:
            return
        revoked_sessions = await self.session_revocation.persist(
            client_id=updated.client_id
        )
        logger.info(
            "OAuth2 client policy narrowed client_id=%s revoked_sessions=%s",
            updated.client_id,
            revoked_sessions,
        )

    async def list_clients(
        self, *, operator_ctx: UserPrincipalContext, offset: int, limit: int
    ) -> list[OAuth2ClientReadDTO]:
        """List one deterministic page of globally registered OAuth2 clients."""
        require_operator(operator_ctx)
        rows = (
            await self.db_session.scalars(
                select(OAuth2ClientDB)
                .order_by(OAuth2ClientDB.client_id)
                .offset(offset)
                .limit(limit)
            )
        ).all()
        return [OAuth2ClientReadDTO.model_validate(row) for row in rows]

    async def count_clients(self, *, operator_ctx: UserPrincipalContext) -> int:
        """Count globally registered OAuth2 clients."""
        require_operator(operator_ctx)
        return int(
            await self.db_session.scalar(
                select(func.count()).select_from(OAuth2ClientDB)
            )
            or 0
        )

    async def read_client(
        self, *, client_id: str, operator_ctx: UserPrincipalContext
    ) -> OAuth2ClientReadDTO:
        """Read one global OAuth2 client."""
        require_operator(operator_ctx)
        client = await self._read_client(client_id)
        if client is None:
            raise OAuth2ClientAdminNotFoundError
        return client

    async def replace_client(
        self,
        *,
        client_id: str,
        dto: OAuth2ClientRegistryReplaceDTO,
        operator_ctx: UserPrincipalContext,
    ) -> OAuth2ClientReadDTO:
        """Replace one global OAuth2 client registration."""
        require_operator(operator_ctx)
        self.policy.validate(
            grant_types=dto.grant_types,
            redirect_uris=dto.redirect_uris,
            is_confidential=dto.is_confidential,
            requires_consent=dto.requires_consent,
        )
        existing = await self._read_client(client_id)
        if existing is None:
            raise OAuth2ClientAdminNotFoundError
        if dto.is_confidential != existing.is_confidential:
            raise InvalidOAuth2ClientPayloadError(ERR_CLIENT_TYPE_IMMUTABLE)
        if dto.is_confidential and existing.client_secret is None:
            raise InvalidOAuth2ClientPayloadError(ERR_CLIENT_SECRET_ROTATION_REQUIRED)

        new_access = dto.user_organization_access
        if (
            existing.machine_organization_access
            != OAuth2ClientMachineOrganizationAccess.NONE
            and "client_credentials" not in dto.grant_types
        ):
            raise OAuth2ClientOrganizationAccessConflictError(
                ERR_MACHINE_REQUIRES_CLIENT_CREDENTIALS
            )
        if (
            new_access == OAuth2ClientUserOrganizationAccess.SINGLE
            and existing.user_organization_access
            == OAuth2ClientUserOrganizationAccess.SELECTED
            and (
                await self.db_session.scalar(
                    select(func.count())
                    .select_from(OAuth2ClientUserOrganizationDB)
                    .where(
                        OAuth2ClientUserOrganizationDB.client_id
                        == self._client_internal_id(client_id)
                    )
                )
            )
            != 1
        ):
            raise OAuth2ClientOrganizationAccessConflictError(
                ERR_USER_ORGANIZATION_ACCESS_INVALID
            )
        if new_access == OAuth2ClientUserOrganizationAccess.UNRESTRICTED:
            await self._replace_user_organizations(
                client_id=client_id, organization_ids=[]
            )

        client = await self._update_client(
            client_id=client_id,
            data=OAuth2ClientPersistenceUpdateDTO(
                client_secret=existing.client_secret,
                name=dto.name,
                grant_types=dto.grant_types,
                scopes=dto.scopes,
                redirect_uris=dto.redirect_uris,
                is_confidential=dto.is_confidential,
                requires_consent=dto.requires_consent,
                is_active=dto.is_active,
                user_organization_access=new_access,
                machine_organization_access=existing.machine_organization_access,
            ),
        )
        await self._revoke_if_client_capabilities_narrowed(
            existing=existing, updated=client
        )
        logger.info(
            (
                "event=oauth2_client_replaced outcome=attempted client_id=%s "
                "subject_id=%s confidential=%s active=%s grant_types=%s"
            ),
            client.client_id,
            format_user_id(operator_ctx.user_public_id)
            if operator_ctx.user_public_id
            else "unknown",
            client.is_confidential,
            client.is_active,
            ",".join(client.grant_types),
        )
        await self.db_session.flush()
        return client

    async def delete_client(
        self,
        *,
        client_id: str,
        operator_ctx: UserPrincipalContext,
    ) -> None:
        """Delete one global OAuth2 client."""
        require_operator(operator_ctx)
        deleted = await self.db_session.scalar(
            delete(OAuth2ClientDB)
            .where(OAuth2ClientDB.client_id == client_id)
            .returning(OAuth2ClientDB.id)
        )
        if deleted is None:
            raise OAuth2ClientAdminNotFoundError
        logger.info(
            "event=oauth2_client_deleted outcome=attempted client_id=%s subject_id=%s",
            client_id,
            format_user_id(operator_ctx.user_public_id)
            if operator_ctx.user_public_id
            else "unknown",
        )
        await self.db_session.flush()

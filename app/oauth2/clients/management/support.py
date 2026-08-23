"""Shared persistence helpers for OAuth2 client administration services."""

from sqlalchemy import delete, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.selectable import ScalarSelect

from app.db.models.oauth2_client import (
    OAuth2ClientDB,
    OAuth2ClientMachineOrganizationDB,
    OAuth2ClientUserOrganizationDB,
)
from app.db.models.organization import OrganizationDB
from app.identity.dtos import IdentityOrganizationDTO
from app.identity.mapping import to_organization
from app.identity.public_ids import parse_organization_id
from app.oauth2.clients.dtos import (
    OAuth2ClientPersistenceUpdateDTO,
    OAuth2ClientReadDTO,
)
from app.oauth2.clients.management.errors import (
    InvalidOAuth2ClientPayloadError,
    OAuth2ClientAdminNotFoundError,
)
from app.oauth2.clients.session_revocation import OAuth2ClientSessionRevocationService
from app.oauth2.specs import OAuth2Specs


ERR_INVALID_ORGANIZATION_ID = "invalid_organization_id"
ERR_ORGANIZATION_NOT_FOUND = "organization_not_found"
type OAuth2ClientOrganizationAssignmentDB = (
    OAuth2ClientMachineOrganizationDB | OAuth2ClientUserOrganizationDB
)


class OAuth2ClientManagementSupport:
    """Share focused client-administration persistence operations."""

    def __init__(self, *, db_session: AsyncSession) -> None:
        """Initialize shared persistence and revocation collaborators."""
        self.db_session = db_session
        self.session_revocation = OAuth2ClientSessionRevocationService(
            db_session=db_session
        )

    async def _read_client(self, client_id: str) -> OAuth2ClientReadDTO | None:
        """Read one client registration by its public protocol identifier."""
        row = await self.db_session.scalar(
            select(OAuth2ClientDB).where(OAuth2ClientDB.client_id == client_id)
        )
        return OAuth2ClientReadDTO.model_validate(row) if row is not None else None

    def _client_internal_id(self, client_id: str) -> ScalarSelect[int]:
        """Return the internal client identifier as a scalar subquery."""
        return (
            select(OAuth2ClientDB.id)
            .where(OAuth2ClientDB.client_id == client_id)
            .scalar_subquery()
        )

    async def _list_organization_assignments(
        self,
        *,
        client_id: str,
        assignment_model: type[OAuth2ClientOrganizationAssignmentDB],
    ) -> list[IdentityOrganizationDTO]:
        """List explicitly assigned organizations in deterministic order."""
        rows = (
            await self.db_session.scalars(
                select(OrganizationDB)
                .join(
                    assignment_model,
                    assignment_model.organization_id == OrganizationDB.id,
                )
                .where(
                    assignment_model.client_id == self._client_internal_id(client_id)
                )
                .order_by(OrganizationDB.id)
            )
        ).all()
        return [to_organization(row) for row in rows]

    async def _list_user_organizations(
        self, *, client_id: str
    ) -> list[IdentityOrganizationDTO]:
        """List organizations assigned to user-backed grants."""
        return await self._list_organization_assignments(
            client_id=client_id,
            assignment_model=OAuth2ClientUserOrganizationDB,
        )

    async def _list_machine_organizations(
        self, *, client_id: str
    ) -> list[IdentityOrganizationDTO]:
        """List organizations assigned to the machine principal."""
        return await self._list_organization_assignments(
            client_id=client_id,
            assignment_model=OAuth2ClientMachineOrganizationDB,
        )

    async def _resolve_organizations(
        self, organization_ids: list[str]
    ) -> list[IdentityOrganizationDTO]:
        """Resolve one bounded assignment set with a single SQLite query."""
        if len(organization_ids) > OAuth2Specs.CLIENT_ORGANIZATION_ASSIGNMENTS_MAX:
            raise InvalidOAuth2ClientPayloadError(ERR_INVALID_ORGANIZATION_ID)
        try:
            public_ids = [parse_organization_id(value) for value in organization_ids]
        except ValueError as exc:
            raise InvalidOAuth2ClientPayloadError(ERR_INVALID_ORGANIZATION_ID) from exc
        if len(public_ids) != len(set(public_ids)):
            raise InvalidOAuth2ClientPayloadError(ERR_INVALID_ORGANIZATION_ID)
        if not public_ids:
            return []

        rows = (
            await self.db_session.scalars(
                select(OrganizationDB).where(
                    OrganizationDB.public_id.in_([int(value) for value in public_ids])
                )
            )
        ).all()
        organizations_by_public_id = {
            int(row.public_id): to_organization(row) for row in rows
        }
        if len(organizations_by_public_id) != len(public_ids):
            raise InvalidOAuth2ClientPayloadError(ERR_ORGANIZATION_NOT_FOUND)
        return [organizations_by_public_id[int(value)] for value in public_ids]

    async def _replace_organization_assignments(
        self,
        *,
        client_id: str,
        organization_ids: list[int],
        assignment_model: type[OAuth2ClientOrganizationAssignmentDB],
    ) -> None:
        """Replace one client's explicit organization assignment set."""
        internal_id = self._client_internal_id(client_id)
        await self.db_session.execute(
            delete(assignment_model).where(assignment_model.client_id == internal_id)
        )
        if organization_ids:
            client_db_id = await self.db_session.scalar(
                select(OAuth2ClientDB.id).where(OAuth2ClientDB.client_id == client_id)
            )
            if client_db_id is None:
                raise OAuth2ClientAdminNotFoundError
            await self.db_session.execute(
                insert(assignment_model),
                [
                    {"client_id": client_db_id, "organization_id": organization_id}
                    for organization_id in organization_ids
                ],
            )
        await self.db_session.flush()

    async def _replace_user_organizations(
        self, *, client_id: str, organization_ids: list[int]
    ) -> None:
        """Replace user-backed organization assignments."""
        await self._replace_organization_assignments(
            client_id=client_id,
            organization_ids=organization_ids,
            assignment_model=OAuth2ClientUserOrganizationDB,
        )

    async def _replace_machine_organizations(
        self, *, client_id: str, organization_ids: list[int]
    ) -> None:
        """Replace machine-principal organization assignments."""
        await self._replace_organization_assignments(
            client_id=client_id,
            organization_ids=organization_ids,
            assignment_model=OAuth2ClientMachineOrganizationDB,
        )

    async def _update_client(
        self, *, client_id: str, data: OAuth2ClientPersistenceUpdateDTO
    ) -> OAuth2ClientReadDTO:
        """Persist and return one complete mutable client representation."""
        row = await self.db_session.scalar(
            update(OAuth2ClientDB)
            .where(OAuth2ClientDB.client_id == client_id)
            .values(**data.model_dump())
            .returning(OAuth2ClientDB)
        )
        if row is None:
            raise OAuth2ClientAdminNotFoundError
        await self.db_session.flush()
        return OAuth2ClientReadDTO.model_validate(row)

"""Organization-scoped metadata service."""

from logging import getLogger

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.helpers import map_integrity_error
from app.db.models.organization import OrganizationDB
from app.enums import Role
from app.errors import ForbiddenOperationError, ObjectNotFoundError
from app.identity.organizations.dtos import OrganizationReadDTO, OrganizationUpdateDTO
from app.security.dtos import UserPrincipalContext


logger = getLogger(__name__)


class OrganizationMetadataService:
    """Manage metadata for the authenticated user's organization."""

    def __init__(
        self, *, db_session: AsyncSession, user_ctx: UserPrincipalContext
    ) -> None:
        """Initialize organization metadata administration."""
        self.db_session = db_session
        self.actor_ctx = user_ctx

    def _require_actor(self) -> None:
        """Require an organization administrator at the service boundary."""
        if Role.ORGANIZATION_ADMIN not in self.actor_ctx.roles:
            raise ForbiddenOperationError

    async def get(self) -> OrganizationReadDTO:
        """Read the authenticated user's organization metadata."""
        self._require_actor()
        row = await self._get_row()
        return OrganizationReadDTO.model_validate(row)

    async def update(self, *, dto: OrganizationUpdateDTO) -> OrganizationReadDTO:
        """Update the authenticated user's organization metadata."""
        self._require_actor()
        row = await self._get_row()
        try:
            async with self.db_session.begin_nested():
                row.name = dto.name
                await self.db_session.flush()
            await self.db_session.refresh(row)
        except IntegrityError as exc:
            raise map_integrity_error(exc) from exc
        return OrganizationReadDTO.model_validate(row)

    async def _get_row(self) -> OrganizationDB:
        """Resolve the organization selected by the authenticated principal."""
        row = await self.db_session.scalar(
            select(OrganizationDB).where(
                OrganizationDB.id == self.actor_ctx.organization_id
            )
        )
        if row is None:
            logger.error(
                "%s with id %s not found.",
                OrganizationDB.__name__,
                self.actor_ctx.organization_id,
            )
            raise ObjectNotFoundError
        return row

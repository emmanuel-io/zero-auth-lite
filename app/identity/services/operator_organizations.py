"""Server-operator organization service."""

from sqlalchemy import func, insert, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.helpers import map_integrity_error
from app.db.models.organization import OrganizationDB
from app.errors import ForbiddenOperationError, ObjectNotFoundError
from app.identity.organizations.dtos import (
    OrganizationCreateDTO,
    OrganizationReadDTO,
    OrganizationUpdateDTO,
)
from app.public_ids import PublicId
from app.security.dtos import UserPrincipalContext


class OperatorOrganizationsService:
    """Manage organizations through the server-operator boundary."""

    def __init__(
        self, *, db_session: AsyncSession, user_ctx: UserPrincipalContext
    ) -> None:
        """Initialize server-wide organization administration."""
        self.db_session = db_session
        self.actor_ctx = user_ctx

    def _require_actor(self) -> None:
        """Require server-operator authority."""
        if not self.actor_ctx.is_operator:
            raise ForbiddenOperationError

    async def list(
        self, *, offset: int = 0, limit: int = 20
    ) -> list[OrganizationReadDTO]:
        """List organizations through the operator boundary."""
        self._require_actor()
        rows = await self.db_session.scalars(
            select(OrganizationDB)
            .order_by(func.lower(OrganizationDB.name), OrganizationDB.id)
            .offset(offset)
            .limit(limit)
        )
        return [OrganizationReadDTO.model_validate(row) for row in rows]

    async def count(self) -> int:
        """Count all organizations through the operator boundary."""
        self._require_actor()
        return int(
            await self.db_session.scalar(
                select(func.count()).select_from(OrganizationDB)
            )
            or 0
        )

    async def create(self, *, dto: OrganizationCreateDTO) -> OrganizationReadDTO:
        """Create an organization through the operator boundary."""
        self._require_actor()
        try:
            async with self.db_session.begin_nested():
                row = (
                    await self.db_session.execute(
                        insert(OrganizationDB)
                        .values(**dto.model_dump())
                        .returning(OrganizationDB)
                    )
                ).scalar_one()
                await self.db_session.flush()
        except IntegrityError as exc:
            raise map_integrity_error(exc) from exc
        return OrganizationReadDTO.model_validate(row)

    async def get(self, *, organization_id: PublicId) -> OrganizationReadDTO:
        """Retrieve an organization by public ID."""
        self._require_actor()
        row = await self._get_row(organization_id=organization_id)
        return OrganizationReadDTO.model_validate(row)

    async def update(
        self, *, organization_id: PublicId, dto: OrganizationUpdateDTO
    ) -> OrganizationReadDTO:
        """Update an organization through the operator boundary."""
        self._require_actor()
        row = await self._get_row(organization_id=organization_id)
        try:
            async with self.db_session.begin_nested():
                row.name = dto.name
                await self.db_session.flush()
            await self.db_session.refresh(row)
        except IntegrityError as exc:
            raise map_integrity_error(exc) from exc
        return OrganizationReadDTO.model_validate(row)

    async def _get_row(self, *, organization_id: PublicId) -> OrganizationDB:
        """Resolve an organization by public ID."""
        row = await self.db_session.scalar(
            select(OrganizationDB).where(OrganizationDB.public_id == organization_id)
        )
        if row is None:
            raise ObjectNotFoundError
        return row

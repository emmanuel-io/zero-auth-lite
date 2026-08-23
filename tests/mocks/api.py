"""Fake API services for route handler tests."""
# ruff: noqa: ANN401, ARG002

from typing import Any

from app.identity.organizations.dtos import OrganizationReadDTO
from app.identity.users.criteria import (
    OperatorUserSearchCriteriaDTO,
    OrganizationUserSearchCriteriaDTO,
    UserPageDTO,
)
from app.identity.users.dtos import (
    OperatorUserCreateDTO,
    OperatorUserPatchDTO,
    OperatorUserReplaceDTO,
    OrganizationUserCreateDTO,
    OrganizationUserPatchDTO,
    OrganizationUserReadDTO,
    OrganizationUserReplaceDTO,
    UserPasswordChangeDTO,
    UserReadDTO,
    UserSelfPatchDTO,
    UserSelfReadDTO,
)
from app.public_ids import PublicId

from tests.fixtures.api import (
    organization_user_read,
    TEST_ORGANIZATION_PUBLIC_ID,
    user_read,
    user_self_read,
)


class FakeUserSelfService:
    """Fake current-user service."""

    def __init__(self) -> None:
        """Initialize recorded self-service effects."""
        self.deleted = False
        self.password_changed = False

    async def read(self) -> UserSelfReadDTO:
        """Return a current-user profile."""
        return user_self_read()

    async def patch(self, *, data: UserSelfPatchDTO) -> UserSelfReadDTO:
        """Return a patched current-user profile."""
        return user_self_read(email=str(data.email or "user@example.com"))

    async def change_password(self, *, data: UserPasswordChangeDTO) -> None:
        """Record a password change."""
        self.password_changed = True

    async def delete(self) -> None:
        """Record account deletion."""
        self.deleted = True


class FakeOrganizationMetadataService:
    """Fake organization-scoped metadata administration."""

    async def get(self) -> OrganizationReadDTO:
        """Return the fake current organization."""
        return OrganizationReadDTO(
            public_id=TEST_ORGANIZATION_PUBLIC_ID,
            name="Organization",
        )

    async def update(self, *, dto: Any) -> OrganizationReadDTO:
        """Return the fake updated current organization."""
        return OrganizationReadDTO(
            public_id=TEST_ORGANIZATION_PUBLIC_ID,
            name=dto.name,
        )


class FakeOrganizationUsersService:
    """Fake organization-scoped user administration."""

    def __init__(self) -> None:
        """Initialize recorded user operations."""
        self.criteria: OrganizationUserSearchCriteriaDTO | None = None
        self.target: PublicId | None = None

    async def search(
        self, *, criteria: OrganizationUserSearchCriteriaDTO
    ) -> UserPageDTO[OrganizationUserReadDTO]:
        """Return one organization user and record criteria."""
        self.criteria = criteria
        return UserPageDTO(items=[organization_user_read()], total=1)

    async def get(self, *, user_id: PublicId) -> OrganizationUserReadDTO:
        """Return one organization user."""
        self.target = user_id
        return organization_user_read(public_id=int(user_id))

    async def create(
        self, *, dto: OrganizationUserCreateDTO
    ) -> OrganizationUserReadDTO:
        """Return a created organization user."""
        return organization_user_read(email=str(dto.email))

    async def resend_invitation(self, *, user_id: PublicId) -> None:
        """Record an invitation target."""
        self.target = user_id

    async def patch(
        self, *, user_id: PublicId, dto: OrganizationUserPatchDTO
    ) -> OrganizationUserReadDTO:
        """Return a patched organization user."""
        self.target = user_id
        return organization_user_read(email=str(dto.email or "user@example.com"))

    async def replace(
        self, *, user_id: PublicId, dto: OrganizationUserReplaceDTO
    ) -> OrganizationUserReadDTO:
        """Return a replaced organization user."""
        self.target = user_id
        return organization_user_read(email=str(dto.email))

    async def delete(self, *, user_id: PublicId) -> None:
        """Record a deleted organization user."""
        self.target = user_id


class FakeOperatorOrganizationsService:
    """Fake server-operator organization administration."""

    def __init__(self) -> None:
        """Initialize recorded organization operations."""
        self.organization_id: PublicId | None = None
        self.offset: int | None = None
        self.limit: int | None = None

    async def list(
        self, *, offset: int = 0, limit: int = 20
    ) -> list[OrganizationReadDTO]:
        """Return globally listed organizations."""
        self.offset = offset
        self.limit = limit
        return [
            OrganizationReadDTO(
                public_id=TEST_ORGANIZATION_PUBLIC_ID,
                name="Organization",
            )
        ]

    async def count(self) -> int:
        """Return the global organization count."""
        return 1

    async def create(self, *, dto: Any) -> OrganizationReadDTO:
        """Return a globally created organization."""
        return OrganizationReadDTO(public_id=TEST_ORGANIZATION_PUBLIC_ID, name=dto.name)

    async def get(self, *, organization_id: PublicId) -> OrganizationReadDTO:
        """Return a globally fetched organization."""
        self.organization_id = organization_id
        return OrganizationReadDTO(public_id=int(organization_id), name="Organization")

    async def update(
        self, *, organization_id: PublicId, dto: Any
    ) -> OrganizationReadDTO:
        """Return a globally patched organization."""
        self.organization_id = organization_id
        return OrganizationReadDTO(public_id=int(organization_id), name=dto.name)


class FakeOperatorUsersService:
    """Fake server-operator user administration."""

    def __init__(self) -> None:
        """Initialize recorded operator user operations."""
        self.criteria: OperatorUserSearchCriteriaDTO | None = None
        self.target: PublicId | None = None
        self.organization_id: PublicId | None = None

    async def search(
        self, *, criteria: OperatorUserSearchCriteriaDTO
    ) -> UserPageDTO[UserReadDTO]:
        """Return one global user and record criteria."""
        self.criteria = criteria
        return UserPageDTO(items=[user_read()], total=1)

    async def get(self, *, user_id: PublicId) -> UserReadDTO:
        """Return one global user."""
        self.target = user_id
        return user_read(public_id=int(user_id))

    async def create(self, *, dto: OperatorUserCreateDTO) -> UserReadDTO:
        """Return a globally created user."""
        self.organization_id = dto.organization_id
        return user_read(email=str(dto.email))

    async def resend_invitation(self, *, user_id: PublicId) -> None:
        """Record an invitation target."""
        self.target = user_id

    async def patch(
        self,
        *,
        user_id: PublicId,
        dto: OperatorUserPatchDTO,
    ) -> UserReadDTO:
        """Return a globally patched user."""
        self.target = user_id
        self.organization_id = dto.organization_id
        return user_read(email=str(dto.email or "user@example.com"))

    async def replace(
        self,
        *,
        user_id: PublicId,
        dto: OperatorUserReplaceDTO,
    ) -> UserReadDTO:
        """Return a globally replaced user."""
        self.target = user_id
        self.organization_id = dto.organization_id
        return user_read(email=str(dto.email))

    async def delete(self, *, user_id: PublicId) -> None:
        """Record a deleted global user."""
        self.target = user_id

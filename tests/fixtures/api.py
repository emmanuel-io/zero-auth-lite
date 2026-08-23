"""Shared helpers for API v1 route handler tests."""

from datetime import datetime, UTC

from app.identity.organizations.dtos import OrganizationSelfReadDTO
from app.identity.users.dtos import (
    OrganizationUserReadDTO,
    UserReadDTO,
    UserSelfReadDTO,
)
from app.identity.users.enums import OrganizationUserRole
from app.public_ids import PublicId


TEST_USER_PUBLIC_ID = 1234
TEST_ORGANIZATION_PUBLIC_ID = 2222
TEST_LIST_LIMIT = 10
TEST_LIST_OFFSET = 2
TEST_PASSWORD = "S3cretPass1!"  # noqa: S105


def user_read(
    public_id: int = TEST_USER_PUBLIC_ID,
    email: str = "user@example.com",
) -> UserReadDTO:
    """Create a user read DTO."""
    now = datetime.now(UTC)
    return UserReadDTO(
        public_id=public_id,
        email=email,
        first_name="Test",
        last_name="User",
        is_active=True,
        role=OrganizationUserRole.MEMBER,
        email_verified=True,
        organization_id=PublicId(TEST_ORGANIZATION_PUBLIC_ID),
        created_at=now,
        updated_at=now,
    )


def organization_user_read(
    public_id: int = TEST_USER_PUBLIC_ID,
    email: str = "user@example.com",
) -> OrganizationUserReadDTO:
    """Create an organization-scoped user read DTO."""
    now = datetime.now(UTC)
    return OrganizationUserReadDTO(
        public_id=public_id,
        email=email,
        first_name="Test",
        last_name="User",
        is_active=True,
        role=OrganizationUserRole.MEMBER,
        email_verified=True,
        created_at=now,
        updated_at=now,
    )


def user_self_read(email: str = "user@example.com") -> UserSelfReadDTO:
    """Create a current-user profile DTO."""
    now = datetime.now(UTC)
    return UserSelfReadDTO(
        email=email,
        first_name="Test",
        last_name="User",
        is_active=True,
        role=OrganizationUserRole.MEMBER,
        email_verified=True,
        organization=OrganizationSelfReadDTO(name="Test Organization"),
        created_at=now,
        updated_at=now,
    )

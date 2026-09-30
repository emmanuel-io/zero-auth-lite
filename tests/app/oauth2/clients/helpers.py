"""Shared persistence setup for OAuth2 client service tests."""

import base64

from app.db.models.oauth2_client import OAuth2ClientDB
from app.db.models.organization import OrganizationDB
from app.password.pwdlib_hasher import PwdlibPasswordHasher
from fastapi import FastAPI
from sqlalchemy import insert

from tests.identifiers import deterministic_uuid


PASSWORD = "client-secret"  # noqa: S105
HASHER = PwdlibPasswordHasher()
PUBLIC_ID = deterministic_uuid("public")
CONFIDENTIAL_ID = deterministic_uuid("confidential")
INACTIVE_ID = deterministic_uuid("inactive")
NO_GRANT_ID = deterministic_uuid("nogrant")


def basic(client_id: str, secret: str) -> str:
    """Build one HTTP Basic credential value."""
    encoded = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return f"Basic {encoded}"


async def seed_clients(app: FastAPI) -> tuple[int, int, int, int]:
    """Create public, confidential, inactive, and machine clients."""
    async with app.state.core_session_factory() as session:
        organization_ids = (
            (
                await session.execute(
                    insert(OrganizationDB)
                    .values([{"name": "Allowed"}, {"name": "Denied"}])
                    .returning(OrganizationDB.id)
                )
            )
            .scalars()
            .all()
        )
        rows = (
            (
                await session.execute(
                    insert(OAuth2ClientDB)
                    .values(
                        [
                            {
                                "client_id": PUBLIC_ID,
                                "client_secret": None,
                                "name": "Public",
                                "grant_types": ["authorization_code"],
                                "scopes": ["read"],
                                "redirect_uris": [],
                                "is_confidential": False,
                                "is_active": True,
                            },
                            {
                                "client_id": CONFIDENTIAL_ID,
                                "client_secret": HASHER.hash(PASSWORD),
                                "name": "Confidential",
                                "grant_types": ["client_credentials"],
                                "scopes": ["read"],
                                "redirect_uris": [],
                                "is_confidential": True,
                                "is_active": True,
                                "machine_organization_access": "selected",
                            },
                            {
                                "client_id": INACTIVE_ID,
                                "client_secret": None,
                                "name": "Inactive",
                                "grant_types": ["authorization_code"],
                                "scopes": ["read"],
                                "redirect_uris": [],
                                "is_confidential": False,
                                "is_active": False,
                            },
                            {
                                "client_id": NO_GRANT_ID,
                                "client_secret": None,
                                "name": "No grant",
                                "grant_types": ["authorization_code"],
                                "scopes": ["read"],
                                "redirect_uris": [],
                                "is_confidential": False,
                                "is_active": True,
                                "machine_organization_access": "unrestricted",
                            },
                        ]
                    )
                    .returning(OAuth2ClientDB.id)
                )
            )
            .scalars()
            .all()
        )
        await session.commit()
        return (
            int(rows[0]),
            int(rows[1]),
            int(organization_ids[0]),
            int(organization_ids[1]),
        )

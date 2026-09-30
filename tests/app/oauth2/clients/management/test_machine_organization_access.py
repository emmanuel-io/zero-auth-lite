"""Branch tests for OAuth2 client machine-organization access persistence."""

import pytest
from app.db.models.organization import OrganizationDB
from app.oauth2.clients.dtos import OAuth2ClientMachineOrganizationUpdateDTO
from app.oauth2.clients.management.errors import (
    InvalidOAuth2ClientPayloadError,
    OAuth2ClientManagementNotFoundError,
    OAuth2ClientOrganizationAccessConflictError,
)
from app.oauth2.clients.management.machine_organization_access import (
    OAuth2ClientMachineOrganizationAccessService,
)
from app.security.principals import BrowserUserPrincipalContext
from app.security.roles import Role
from fastapi import FastAPI

from tests.app.oauth2.clients.helpers import seed_clients
from tests.identifiers import (
    deterministic_uuid,
    format_public_id as format_organization_id,
    PublicId,
)


pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_client_administration_direct_persistence_branches(
    app: FastAPI,
) -> None:
    """Exercise machine-organization assignments and validation."""

    _, _, first_organization_id, second_organization_id = await seed_clients(app)
    ctx = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=first_organization_id,
        raw_session_id="session",
        user_public_id=PublicId(1),
        organization_public_id=PublicId(1),
        roles=frozenset({Role.OPERATOR}),
    )
    async with app.state.core_session_factory() as session:
        machine_organization_service = OAuth2ClientMachineOrganizationAccessService(
            db_session=session
        )
        first_organization = await session.get(OrganizationDB, first_organization_id)
        second_organization = await session.get(OrganizationDB, second_organization_id)
        assert first_organization is not None
        assert second_organization is not None
        first_public = format_organization_id(first_organization.public_id)
        second_public = format_organization_id(second_organization.public_id)
        selected = (
            await machine_organization_service.replace_machine_organization_access(
                client_id=deterministic_uuid("confidential"),
                dto=OAuth2ClientMachineOrganizationUpdateDTO(
                    machine_organization_access="selected",
                    organization_ids=[first_public, second_public],
                ),
                operator_ctx=ctx,
            )
        )
        assert set(selected.organization_ids) == {
            first_organization.public_id,
            second_organization.public_id,
        }
        single = await machine_organization_service.replace_machine_organization_access(
            client_id=deterministic_uuid("confidential"),
            dto=OAuth2ClientMachineOrganizationUpdateDTO(
                machine_organization_access="single", organization_ids=[first_public]
            ),
            operator_ctx=ctx,
        )
        assert single.organization_ids == [first_organization.public_id]
        cleared = (
            await machine_organization_service.replace_machine_organization_access(
                client_id=deterministic_uuid("confidential"),
                dto=OAuth2ClientMachineOrganizationUpdateDTO(
                    machine_organization_access="none"
                ),
                operator_ctx=ctx,
            )
        )
        assert cleared.organization_ids == []
        invalid_payloads = [
            OAuth2ClientMachineOrganizationUpdateDTO(
                machine_organization_access="none", organization_ids=[first_public]
            ),
            OAuth2ClientMachineOrganizationUpdateDTO(
                machine_organization_access="single", organization_ids=[]
            ),
            OAuth2ClientMachineOrganizationUpdateDTO(
                machine_organization_access="selected", organization_ids=[]
            ),
        ]
        for invalid in invalid_payloads:
            with pytest.raises(OAuth2ClientOrganizationAccessConflictError):
                await machine_organization_service.replace_machine_organization_access(
                    client_id=deterministic_uuid("confidential"),
                    dto=invalid,
                    operator_ctx=ctx,
                )
        with pytest.raises(InvalidOAuth2ClientPayloadError):
            await machine_organization_service.replace_machine_organization_access(
                client_id=deterministic_uuid("confidential"),
                dto=OAuth2ClientMachineOrganizationUpdateDTO(
                    machine_organization_access="selected",
                    organization_ids=[deterministic_uuid("missing-organization")],
                ),
                operator_ctx=ctx,
            )
        with pytest.raises(OAuth2ClientOrganizationAccessConflictError):
            await machine_organization_service.replace_machine_organization_access(
                client_id=deterministic_uuid("public"),
                dto=OAuth2ClientMachineOrganizationUpdateDTO(
                    machine_organization_access="unrestricted"
                ),
                operator_ctx=ctx,
            )
        with pytest.raises(OAuth2ClientManagementNotFoundError):
            await machine_organization_service._replace_machine_organizations(  # noqa: SLF001
                client_id=deterministic_uuid("missing"),
                organization_ids=[first_organization_id],
            )

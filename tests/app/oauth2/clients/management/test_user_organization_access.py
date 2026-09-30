"""Branch tests for OAuth2 client user-organization access persistence."""

import pytest
from app.db.models.organization import OrganizationDB
from app.oauth2.clients.access import OAuth2ClientUserOrganizationAccess
from app.oauth2.clients.dtos import OAuth2ClientUserOrganizationUpdateDTO
from app.oauth2.clients.management.errors import (
    InvalidOAuth2ClientPayloadError,
    OAuth2ClientOrganizationAccessConflictError,
)
from app.oauth2.clients.management.user_organization_access import (
    OAuth2ClientUserOrganizationAccessService,
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
    """Exercise user-organization assignments and validation."""

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
        user_organization_service = OAuth2ClientUserOrganizationAccessService(
            db_session=session
        )
        first_organization = await session.get(OrganizationDB, first_organization_id)
        second_organization = await session.get(OrganizationDB, second_organization_id)
        assert first_organization is not None
        assert second_organization is not None
        first_public = format_organization_id(first_organization.public_id)
        second_public = format_organization_id(second_organization.public_id)
        assigned = await user_organization_service.replace_user_organizations(
            client_id=deterministic_uuid("public"),
            dto=OAuth2ClientUserOrganizationUpdateDTO(
                user_organization_access="selected",
                organization_ids=[first_public, second_public],
            ),
            operator_ctx=ctx,
        )
        assert assigned.user_organization_access == "selected"
        assert {item.organization_id for item in assigned.organizations} == {
            first_organization.public_id,
            second_organization.public_id,
        }
        with pytest.raises(OAuth2ClientOrganizationAccessConflictError):
            await user_organization_service.replace_user_organizations(
                client_id=deterministic_uuid("public"),
                dto=OAuth2ClientUserOrganizationUpdateDTO(
                    user_organization_access="unrestricted",
                    organization_ids=[first_public],
                ),
                operator_ctx=ctx,
            )
        with pytest.raises(OAuth2ClientOrganizationAccessConflictError):
            await user_organization_service.replace_user_organizations(
                client_id=deterministic_uuid("public"),
                dto=OAuth2ClientUserOrganizationUpdateDTO(
                    user_organization_access="single", organization_ids=[]
                ),
                operator_ctx=ctx,
            )
        with pytest.raises(OAuth2ClientOrganizationAccessConflictError):
            await user_organization_service.replace_user_organizations(
                client_id=deterministic_uuid("public"),
                dto=OAuth2ClientUserOrganizationUpdateDTO(
                    user_organization_access="selected", organization_ids=[]
                ),
                operator_ctx=ctx,
            )
        with pytest.raises(InvalidOAuth2ClientPayloadError):
            await user_organization_service.replace_user_organizations(
                client_id=deterministic_uuid("public"),
                dto=OAuth2ClientUserOrganizationUpdateDTO(
                    user_organization_access=OAuth2ClientUserOrganizationAccess.SELECTED,
                    organization_ids=[deterministic_uuid("missing-organization")],
                ),
                operator_ctx=ctx,
            )
        with pytest.raises(InvalidOAuth2ClientPayloadError):
            await user_organization_service.replace_user_organizations(
                client_id=deterministic_uuid("public"),
                dto=OAuth2ClientUserOrganizationUpdateDTO.model_construct(
                    user_organization_access="selected",  # type: ignore[arg-type]
                    organization_ids=[
                        deterministic_uuid(value) for value in range(1, 102)
                    ],
                ),
                operator_ctx=ctx,
            )

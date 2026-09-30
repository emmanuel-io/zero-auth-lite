"""Branch tests for OAuth2 client organization authorization."""

import pytest
from app.db.models.oauth2_client import (
    OAuth2ClientDB,
    OAuth2ClientMachineOrganizationDB,
    OAuth2ClientUserOrganizationDB,
)
from app.db.models.organization import OrganizationDB
from app.oauth2.clients.access import OAuth2ClientUserOrganizationAccess
from app.oauth2.clients.dtos import OAuth2ClientReadDTO
from app.oauth2.clients.user_organization_authorization import (
    ensure_client_allows_user_organization,
    OAuth2ClientNotAllowedForUserOrganizationError,
)
from app.security.organization_security_session_authorization import (
    MachineClientOrganizationAccessDeniedError,
    OrganizationSecuritySessionAuthorizationService,
)
from app.security.principals import OAuth2ClientPrincipalContext
from fastapi import FastAPI

from tests.identifiers import deterministic_uuid, PublicId

from .helpers import seed_clients


pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_client_organization_policy_decision_branches(app: FastAPI) -> None:
    """Cover unrestricted, selected, missing, disabled, and wrong-principal paths."""

    (
        public_id,
        confidential_id,
        allowed_organization_id,
        denied_organization_id,
    ) = await seed_clients(app)
    async with app.state.core_session_factory() as session:
        session.add_all(
            [
                OAuth2ClientUserOrganizationDB(
                    client_id=confidential_id, organization_id=allowed_organization_id
                ),
                OAuth2ClientMachineOrganizationDB(
                    client_id=confidential_id, organization_id=allowed_organization_id
                ),
            ]
        )
        await session.flush()
        public_row = await session.get(OAuth2ClientDB, public_id)
        confidential_row = await session.get(OAuth2ClientDB, confidential_id)
        assert public_row is not None
        assert confidential_row is not None

        public = OAuth2ClientReadDTO.model_validate(public_row)
        selected = OAuth2ClientReadDTO.model_validate(confidential_row)
        await ensure_client_allows_user_organization(
            client=public, organization_id=denied_organization_id, db_session=session
        )
        selected.user_organization_access = OAuth2ClientUserOrganizationAccess.SELECTED
        await ensure_client_allows_user_organization(
            client=selected, organization_id=allowed_organization_id, db_session=session
        )
        with pytest.raises(OAuth2ClientNotAllowedForUserOrganizationError):
            await ensure_client_allows_user_organization(
                client=selected,
                organization_id=denied_organization_id,
                db_session=session,
            )

        selected.user_organization_access = OAuth2ClientUserOrganizationAccess.SINGLE
        session.add(
            OAuth2ClientUserOrganizationDB(
                client_id=confidential_id,
                organization_id=denied_organization_id,
            )
        )
        await session.flush()
        with pytest.raises(OAuth2ClientNotAllowedForUserOrganizationError):
            await ensure_client_allows_user_organization(
                client=selected,
                organization_id=allowed_organization_id,
                db_session=session,
            )
        extra_user_assignment = await session.get(
            OAuth2ClientUserOrganizationDB,
            (confidential_id, denied_organization_id),
        )
        assert extra_user_assignment is not None
        await session.delete(extra_user_assignment)
        await session.flush()

        authorization_service = OrganizationSecuritySessionAuthorizationService(session)
        principal = OAuth2ClientPrincipalContext(
            organization_id=None,
            oauth2_session_id=1,
            client_id=deterministic_uuid("confidential"),
            scopes=frozenset({"sessions:write"}),
        )
        allowed_row = await session.get(OrganizationDB, allowed_organization_id)
        denied_row = await session.get(OrganizationDB, denied_organization_id)
        assert allowed_row is not None
        assert denied_row is not None
        authorization = await authorization_service.authorize(
            organization_public_id=PublicId(allowed_row.public_id),
            principal=principal,
        )
        assert authorization.organization_id == allowed_organization_id
        confidential_row.machine_organization_access = "single"
        await session.flush()
        session.add(
            OAuth2ClientMachineOrganizationDB(
                client_id=confidential_id,
                organization_id=denied_organization_id,
            )
        )
        await session.flush()
        with pytest.raises(MachineClientOrganizationAccessDeniedError):
            await authorization_service.authorize(
                organization_public_id=PublicId(allowed_row.public_id),
                principal=principal,
            )
        extra_machine_assignment = await session.get(
            OAuth2ClientMachineOrganizationDB,
            (confidential_id, denied_organization_id),
        )
        assert extra_machine_assignment is not None
        await session.delete(extra_machine_assignment)
        await session.flush()
        denied_principals = [
            OAuth2ClientPrincipalContext(
                organization_id=None,
                oauth2_session_id=1,
                client_id=deterministic_uuid("confidential"),
                scopes=frozenset(),
            ),
            OAuth2ClientPrincipalContext(
                organization_id=None,
                oauth2_session_id=1,
                client_id=deterministic_uuid("missing"),
                scopes=frozenset({"read"}),
            ),
            OAuth2ClientPrincipalContext(
                organization_id=None,
                oauth2_session_id=1,
                client_id=deterministic_uuid("nogrant"),
                scopes=frozenset({"sessions:write"}),
            ),
            OAuth2ClientPrincipalContext(
                organization_id=None,
                oauth2_session_id=1,
                client_id=deterministic_uuid("confidential"),
                scopes=frozenset({"read"}),
            ),
        ]
        for denied in denied_principals:
            with pytest.raises(MachineClientOrganizationAccessDeniedError):
                await authorization_service.authorize(
                    principal=denied,
                    organization_public_id=PublicId(denied_row.public_id),
                )

        confidential_row.machine_organization_access = "none"
        await session.flush()
        with pytest.raises(MachineClientOrganizationAccessDeniedError):
            await authorization_service.authorize(
                principal=principal,
                organization_public_id=PublicId(allowed_row.public_id),
            )

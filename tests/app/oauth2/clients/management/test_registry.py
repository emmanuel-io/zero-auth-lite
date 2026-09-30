"""Branch tests for OAuth2 client registry persistence."""

import pytest
from app.core.errors.common import ForbiddenOperationError
from app.oauth2.clients.dtos import OAuth2ClientRegistryReplaceDTO
from app.oauth2.clients.management.errors import (
    InvalidOAuth2ClientPayloadError,
    OAuth2ClientManagementNotFoundError,
)
from app.oauth2.clients.management.policy import OAuth2ClientPolicy
from app.oauth2.clients.management.registry import OAuth2ClientRegistryService
from app.oauth2.grants.types import OAuth2GrantType
from app.oauth2.settings import OAuth2Settings
from app.security.principals import BrowserUserPrincipalContext
from app.security.roles import Role
from fastapi import FastAPI

from tests.app.oauth2.clients.helpers import (
    CONFIDENTIAL_ID,
    INACTIVE_ID,
    NO_GRANT_ID,
    PUBLIC_ID,
    seed_clients,
)
from tests.identifiers import deterministic_uuid, PublicId


pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_client_administration_direct_persistence_branches(
    app: FastAPI,
) -> None:
    """Exercise client reads, updates, validation, and deletion."""
    _, _, first_organization_id, _ = await seed_clients(app)
    ordinary_ctx = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=first_organization_id,
        raw_session_id="session",
        user_public_id=PublicId(1),
        organization_public_id=PublicId(1),
    )
    ctx = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=first_organization_id,
        raw_session_id="session",
        user_public_id=PublicId(1),
        organization_public_id=PublicId(1),
        roles=frozenset({Role.OPERATOR}),
    )
    settings = OAuth2Settings(
        authorization_code_enabled=True,
        client_credentials_enabled=True,
        refresh_token_enabled=True,
    )
    async with app.state.core_session_factory() as session:
        registry_service = OAuth2ClientRegistryService(
            db_session=session, policy=OAuth2ClientPolicy(settings)
        )
        with pytest.raises(ForbiddenOperationError):
            await registry_service.list_clients(
                operator_ctx=ordinary_ctx,
                offset=0,
                limit=20,
            )
        assert {
            item.client_id
            for item in await registry_service.list_clients(
                operator_ctx=ctx,
                offset=0,
                limit=20,
            )
        } == {
            PUBLIC_ID,
            CONFIDENTIAL_ID,
            INACTIVE_ID,
            NO_GRANT_ID,
        }
        assert (
            await registry_service.read_client(client_id=PUBLIC_ID, operator_ctx=ctx)
        ).name
        with pytest.raises(OAuth2ClientManagementNotFoundError):
            await registry_service.read_client(
                client_id=deterministic_uuid("missing"), operator_ctx=ctx
            )

        payload = OAuth2ClientRegistryReplaceDTO(
            name="Updated public",
            grant_types=[OAuth2GrantType.AUTHORIZATION_CODE.value],
            scopes=["read"],
            redirect_uris=["https://client.example/callback"],
            is_confidential=False,
            requires_consent=True,
            is_active=True,
        )
        updated = await registry_service.replace_client(
            client_id=PUBLIC_ID, dto=payload, operator_ctx=ctx
        )
        assert updated.name == "Updated public"
        with pytest.raises(OAuth2ClientManagementNotFoundError):
            await registry_service.replace_client(
                client_id=deterministic_uuid("missing"), dto=payload, operator_ctx=ctx
            )
        with pytest.raises(InvalidOAuth2ClientPayloadError):
            await registry_service.replace_client(
                client_id=PUBLIC_ID,
                dto=payload.model_copy(update={"is_confidential": True}),
                operator_ctx=ctx,
            )
        await registry_service.delete_client(client_id=PUBLIC_ID, operator_ctx=ctx)
        with pytest.raises(OAuth2ClientManagementNotFoundError):
            await registry_service.delete_client(client_id=PUBLIC_ID, operator_ctx=ctx)

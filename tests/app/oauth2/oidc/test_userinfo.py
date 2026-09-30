"""Branch tests for the OIDC UserInfo service."""

import pytest
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.enums import UserEmailStatus
from app.oauth2.errors import (
    OAuth2TokenSessionInvalidError,
    OIDCOpenIDScopeRequiredError,
)
from app.oauth2.oidc.userinfo import OIDCUserInfoService
from app.oauth2.settings import OAuth2Settings
from app.security.principals import OAuth2UserPrincipalContext
from fastapi import FastAPI
from sqlalchemy import insert, select

from tests.app.oauth2.clients.helpers import seed_clients
from tests.identifiers import deterministic_uuid, PublicId


pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_userinfo_direct_service_security_branches(app: FastAPI) -> None:
    """Cover OIDC enablement, scopes, identity eligibility, and optional claims."""

    _, _, organization_id, _ = await seed_clients(app)
    async with app.state.core_session_factory() as session:
        user = (
            await session.execute(
                insert(UserDB)
                .values(
                    first_name="Ada",
                    last_name="Lovelace",
                    hashed_password="unused",  # noqa: S106
                    is_active=True,
                )
                .returning(UserDB)
            )
        ).scalar_one()
        session.add_all(
            [
                UserEmailDB(
                    user_id=user.id,
                    email="oidc@example.test",
                    normalized_email="oidc@example.test",
                    status=UserEmailStatus.CURRENT,
                    verified_at=user.created_at,
                ),
                OrganizationMembershipDB(
                    user_id=user.id,
                    organization_id=organization_id,
                ),
            ]
        )
        await session.flush()
        enabled = OIDCUserInfoService(
            db_session=session, settings=OAuth2Settings(oidc_enabled=True)
        )
        disabled = OIDCUserInfoService(
            db_session=session, settings=OAuth2Settings(oidc_enabled=False)
        )
        full = OAuth2UserPrincipalContext(
            user_id=user.id,
            organization_id=organization_id,
            oauth2_session_id=1,
            client_id=deterministic_uuid("client"),
            user_public_id=PublicId(user.public_id),
            organization_public_id=PublicId(1),
            scopes=frozenset({"openid", "email", "profile"}),
        )
        response = await enabled.get_userinfo(principal_ctx=full)
        assert response["name"] == "Ada Lovelace"
        assert response["email"] == "oidc@example.test"
        subject_only = await enabled.get_userinfo(
            principal_ctx=OAuth2UserPrincipalContext(
                user_id=user.id,
                organization_id=organization_id,
                oauth2_session_id=1,
                client_id=deterministic_uuid("client"),
                user_public_id=PublicId(user.public_id),
                organization_public_id=PublicId(1),
                scopes=frozenset({"openid"}),
            )
        )
        assert set(subject_only) == {"sub"}

        with pytest.raises(OAuth2TokenSessionInvalidError):
            await disabled.get_userinfo(principal_ctx=full)
        with pytest.raises(OIDCOpenIDScopeRequiredError):
            await enabled.get_userinfo(
                principal_ctx=OAuth2UserPrincipalContext(
                    user_id=user.id,
                    organization_id=organization_id,
                    oauth2_session_id=1,
                    client_id=deterministic_uuid("client"),
                    user_public_id=PublicId(user.public_id),
                    organization_public_id=PublicId(1),
                    scopes=frozenset({"profile"}),
                )
            )
        with pytest.raises(OAuth2TokenSessionInvalidError):
            await enabled.get_userinfo(
                principal_ctx=OAuth2UserPrincipalContext(
                    user_id=999999,
                    organization_id=organization_id,
                    oauth2_session_id=1,
                    client_id=deterministic_uuid("client"),
                    user_public_id=PublicId(999999),
                    organization_public_id=PublicId(1),
                    scopes=frozenset({"openid"}),
                )
            )

        user.is_active = False
        await session.flush()
        with pytest.raises(OAuth2TokenSessionInvalidError):
            await enabled.get_userinfo(principal_ctx=full)
        user.is_active = True
        user_email = await session.scalar(
            select(UserEmailDB).where(UserEmailDB.user_id == user.id)
        )
        assert user_email is not None
        user_email.verified_at = None
        await session.flush()
        with pytest.raises(OAuth2TokenSessionInvalidError):
            await enabled.get_userinfo(principal_ctx=full)
        user_email.verified_at = user.created_at
        user.first_name = ""
        user.last_name = ""
        await session.flush()
        minimal = await enabled.get_userinfo(principal_ctx=full)
        assert "name" not in minimal
        assert "given_name" not in minimal
        assert "family_name" not in minimal

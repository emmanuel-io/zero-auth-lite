"""Branch tests for SQLAlchemy-backed OAuth2 service decisions."""

import base64

import pytest
from app.db.models.oauth2_client import (
    OAuth2ClientDB,
    OAuth2ClientMachineOrganizationDB,
    OAuth2ClientUserOrganizationDB,
)
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.enums import Role
from app.errors import ForbiddenOperationError
from app.identity.public_ids import format_organization_id
from app.identity.users.enums import UserEmailStatus
from app.oauth2.clients.access import OAuth2ClientMachineOrganizationAccess
from app.oauth2.clients.auth import (
    authenticate_token_client,
    lock_and_reload_token_client,
)
from app.oauth2.clients.dtos import (
    OAuth2ClientMachineOrganizationUpdateDTO,
    OAuth2ClientReadDTO,
    OAuth2ClientRegistryReplaceDTO,
)
from app.oauth2.clients.management.errors import (
    InvalidOAuth2ClientPayloadError,
    OAuth2ClientAdminNotFoundError,
    OAuth2ClientOrganizationAccessConflictError,
)
from app.oauth2.clients.management.machine_organization_access import (
    OAuth2ClientMachineOrganizationAccessService,
)
from app.oauth2.clients.management.policy import OAuth2ClientPolicy
from app.oauth2.clients.management.registry import OAuth2ClientRegistryService
from app.oauth2.clients.management.user_organization_access import (
    OAuth2ClientUserOrganizationAccessService,
)
from app.oauth2.clients.user_organization_authorization import (
    ensure_client_allows_user_organization,
    OAuth2ClientNotAllowedForUserOrganizationError,
)
from app.oauth2.errors import (
    InvalidClientError,
    OAuth2ProtocolError,
    OAuth2SessionInvalidError,
    OIDCOpenIDScopeRequiredError,
)
from app.oauth2.oidc.userinfo import OIDCUserInfoService
from app.oauth2.settings import OAuth2GrantType, OAuth2Settings
from app.password.pwdlib_hasher import PwdlibPasswordHasher
from app.public_ids import PublicId
from app.security.dtos import (
    BrowserUserPrincipalContext,
    OAuth2ClientPrincipalContext,
    OAuth2UserPrincipalContext,
)
from app.security.organization_security_session_authorization import (
    MachineClientOrganizationAccessDeniedError,
    OrganizationSecuritySessionAuthorizationService,
)
from fastapi import FastAPI
from sqlalchemy import insert, select, update


pytestmark = pytest.mark.integration
PASSWORD = "client-secret"  # noqa: S105
HASHER = PwdlibPasswordHasher()


def basic(client_id: str, secret: str) -> str:
    """Build one HTTP Basic credential value."""
    encoded = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return f"Basic {encoded}"


@pytest.mark.parametrize(
    ("grant_types", "redirect_uris", "confidential", "consent"),
    [
        ([], [], True, True),
        (["unknown"], [], True, True),
        ([OAuth2GrantType.authorization_code], [], True, True),
        ([OAuth2GrantType.client_credentials], [], False, True),
        ([OAuth2GrantType.refresh_token], [], True, True),
        (
            [OAuth2GrantType.authorization_code],
            ["https://client.example/callback"],
            False,
            False,
        ),
    ],
)
def test_client_policy_rejects_each_invalid_configuration(
    grant_types: list[OAuth2GrantType],
    redirect_uris: list[str],
    confidential: bool,  # noqa: FBT001
    consent: bool,  # noqa: FBT001
) -> None:
    """Cover each client-policy rejection independently."""
    policy = OAuth2ClientPolicy(
        OAuth2Settings(
            authorization_code_enabled=True,
            client_credentials_enabled=True,
            refresh_token_enabled=True,
        )
    )
    with pytest.raises(InvalidOAuth2ClientPayloadError):
        policy.validate(
            grant_types=grant_types,
            redirect_uris=redirect_uris,
            is_confidential=confidential,
            requires_consent=consent,
        )


def test_client_policy_accepts_each_supported_flow() -> None:
    """Accept a composable authorization-code and refresh configuration."""
    OAuth2ClientPolicy(
        OAuth2Settings(
            authorization_code_enabled=True,
            refresh_token_enabled=True,
        )
    ).validate(
        grant_types=[
            OAuth2GrantType.authorization_code,
            OAuth2GrantType.refresh_token,
        ],
        redirect_uris=["https://client.example/callback"],
        is_confidential=True,
        requires_consent=True,
    )


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
                                "client_id": "public",
                                "client_secret": None,
                                "name": "Public",
                                "grant_types": ["authorization_code"],
                                "scopes": ["read"],
                                "redirect_uris": [],
                                "is_confidential": False,
                                "is_active": True,
                            },
                            {
                                "client_id": "confidential",
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
                                "client_id": "inactive",
                                "client_secret": None,
                                "name": "Inactive",
                                "grant_types": ["authorization_code"],
                                "scopes": ["read"],
                                "redirect_uris": [],
                                "is_confidential": False,
                                "is_active": False,
                            },
                            {
                                "client_id": "nogrant",
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


@pytest.mark.asyncio
async def test_client_authentication_decision_branches(app: FastAPI) -> None:
    """Cover public, Basic, post, inactive, unknown, and mixed credentials."""
    await seed_clients(app)
    async with app.state.core_session_factory() as session:
        public = await authenticate_token_client(
            db_session=session,
            password_hasher=HASHER,
            client_id="public",
        )
        header = await authenticate_token_client(
            db_session=session,
            password_hasher=HASHER,
            authorization=basic("confidential", PASSWORD),
        )
        post = await authenticate_token_client(
            db_session=session,
            password_hasher=HASHER,
            client_id="confidential",
            client_secret=PASSWORD,
        )
        assert (public.method, header.method, post.method) == (
            "public",
            "basic",
            "post",
        )

        invalid_calls = [
            {"client_id": "missing"},
            {"client_id": "inactive"},
            {"client_id": "confidential"},
            {"client_id": "public", "client_secret": ""},
            {"client_id": "confidential", "client_secret": "wrong"},
            {
                "authorization": basic("missing", PASSWORD),
            },
            {
                "authorization": basic("public", PASSWORD),
            },
            {
                "authorization": basic("confidential", "wrong"),
            },
        ]
        for kwargs in invalid_calls:
            with pytest.raises(InvalidClientError):
                await authenticate_token_client(
                    db_session=session,
                    password_hasher=HASHER,
                    **kwargs,
                )

        protocol_calls = [
            {},
            {
                "authorization": basic("confidential", PASSWORD),
                "client_id": "confidential",
            },
            {
                "client_id": "confidential",
                "client_secret": PASSWORD,
                "allow_client_secret_post": False,
            },
        ]
        for kwargs in protocol_calls:
            with pytest.raises(OAuth2ProtocolError):
                await authenticate_token_client(
                    db_session=session,
                    password_hasher=HASHER,
                    **kwargs,
                )


@pytest.mark.asyncio
async def test_token_client_lock_rejects_a_concurrent_secret_rotation(
    app: FastAPI,
) -> None:
    """Do not issue from client credentials invalidated during verification."""
    await seed_clients(app)
    async with app.state.core_session_factory() as token_session:
        client_auth = await authenticate_token_client(
            db_session=token_session,
            password_hasher=HASHER,
            authorization=basic("confidential", PASSWORD),
        )
        rotated_secret_hash = HASHER.hash("rotated-client-secret")
        async with app.state.core_session_factory.begin() as admin_session:
            await admin_session.execute(
                update(OAuth2ClientDB)
                .where(OAuth2ClientDB.client_id == "confidential")
                .values(client_secret=rotated_secret_hash)
            )

        with pytest.raises(InvalidClientError):
            await lock_and_reload_token_client(token_session, client_auth)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "authorization",
    ["Bearer value", "Basic !!!", "Basic Og==", "Basic"],
)
async def test_malformed_basic_credentials_are_rejected(
    app: FastAPI, authorization: str
) -> None:
    """Reject each malformed Basic parsing branch."""
    async with app.state.core_session_factory() as session:
        with pytest.raises(InvalidClientError):
            await authenticate_token_client(
                db_session=session,
                password_hasher=HASHER,
                authorization=authorization,
            )


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
                    client_id=public_id, organization_id=allowed_organization_id
                ),
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
        selected.user_organization_access = "selected"  # type: ignore[assignment]
        await ensure_client_allows_user_organization(
            client=selected, organization_id=allowed_organization_id, db_session=session
        )
        with pytest.raises(OAuth2ClientNotAllowedForUserOrganizationError):
            await ensure_client_allows_user_organization(
                client=selected,
                organization_id=denied_organization_id,
                db_session=session,
            )

        authorization_service = OrganizationSecuritySessionAuthorizationService(session)
        principal = OAuth2ClientPrincipalContext(
            organization_id=None,
            session_id=1,
            client_id="confidential",
            scopes=frozenset({"users:write"}),
            machine_organization_access=OAuth2ClientMachineOrganizationAccess.SELECTED,
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
        denied_principals = [
            OAuth2ClientPrincipalContext(
                organization_id=None,
                session_id=1,
                client_id="confidential",
                scopes=frozenset(),
                machine_organization_access=OAuth2ClientMachineOrganizationAccess.SELECTED,
            ),
            OAuth2ClientPrincipalContext(
                organization_id=None,
                session_id=1,
                client_id="missing",
                scopes=frozenset({"read"}),
                machine_organization_access=OAuth2ClientMachineOrganizationAccess.SELECTED,
            ),
            OAuth2ClientPrincipalContext(
                organization_id=None,
                session_id=1,
                client_id="nogrant",
                scopes=frozenset({"users:write"}),
                machine_organization_access=OAuth2ClientMachineOrganizationAccess.UNRESTRICTED,
            ),
            OAuth2ClientPrincipalContext(
                organization_id=None,
                session_id=1,
                client_id="confidential",
                scopes=frozenset({"read"}),
                machine_organization_access=OAuth2ClientMachineOrganizationAccess.SELECTED,
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


@pytest.mark.asyncio
async def test_client_administration_direct_persistence_branches(  # noqa: PLR0915
    app: FastAPI,
) -> None:
    """Exercise client reads, updates, assignments, validation, and deletion."""
    _, _, first_organization_id, second_organization_id = await seed_clients(app)
    ordinary_ctx = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=first_organization_id,
        session_id="session",
    )
    ctx = BrowserUserPrincipalContext(
        user_id=1,
        organization_id=first_organization_id,
        session_id="session",
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
        user_organization_service = OAuth2ClientUserOrganizationAccessService(
            db_session=session
        )
        machine_organization_service = OAuth2ClientMachineOrganizationAccessService(
            db_session=session
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
            "public",
            "confidential",
            "inactive",
            "nogrant",
        }
        assert (
            await registry_service.read_client(client_id="public", operator_ctx=ctx)
        ).name
        with pytest.raises(OAuth2ClientAdminNotFoundError):
            await registry_service.read_client(client_id="missing", operator_ctx=ctx)

        payload = OAuth2ClientRegistryReplaceDTO(
            name="Updated public",
            grant_types=[OAuth2GrantType.authorization_code.value],
            scopes=["read"],
            redirect_uris=["https://client.example/callback"],
            is_confidential=False,
            requires_consent=True,
            is_active=True,
            user_organization_access="selected",
        )
        updated = await registry_service.replace_client(
            client_id="public", dto=payload, operator_ctx=ctx
        )
        assert updated.name == "Updated public"
        with pytest.raises(OAuth2ClientAdminNotFoundError):
            await registry_service.replace_client(
                client_id="missing", dto=payload, operator_ctx=ctx
            )
        with pytest.raises(InvalidOAuth2ClientPayloadError):
            await registry_service.replace_client(
                client_id="public",
                dto=payload.model_copy(update={"is_confidential": True}),
                operator_ctx=ctx,
            )
        first_organization = await session.get(OrganizationDB, first_organization_id)
        second_organization = await session.get(OrganizationDB, second_organization_id)
        assert first_organization is not None
        assert second_organization is not None
        first_public = format_organization_id(first_organization.public_id)
        second_public = format_organization_id(second_organization.public_id)
        assigned = await user_organization_service.replace_user_organizations(
            client_id="public",
            organization_ids=[first_public, second_public],
            operator_ctx=ctx,
        )
        assert {item.organization_id for item in assigned.organizations} == {
            first_public,
            second_public,
        }
        public_row = await session.scalar(
            select(OAuth2ClientDB).where(OAuth2ClientDB.client_id == "public")
        )
        assert public_row is not None
        public_row.user_organization_access = "unrestricted"
        await session.flush()
        with pytest.raises(OAuth2ClientOrganizationAccessConflictError):
            await user_organization_service.replace_user_organizations(
                client_id="public",
                organization_ids=[first_public],
                operator_ctx=ctx,
            )
        public_row.user_organization_access = "single"
        await session.flush()
        with pytest.raises(OAuth2ClientOrganizationAccessConflictError):
            await user_organization_service.replace_user_organizations(
                client_id="public", organization_ids=[], operator_ctx=ctx
            )
        public_row.user_organization_access = "selected"
        await session.flush()
        with pytest.raises(InvalidOAuth2ClientPayloadError):
            await user_organization_service.replace_user_organizations(
                client_id="public", organization_ids=["org_bad"], operator_ctx=ctx
            )
        with pytest.raises(InvalidOAuth2ClientPayloadError):
            await user_organization_service.replace_user_organizations(
                client_id="public",
                organization_ids=[format_organization_id(999999999)],
                operator_ctx=ctx,
            )
        with pytest.raises(InvalidOAuth2ClientPayloadError):
            await user_organization_service.replace_user_organizations(
                client_id="public",
                organization_ids=[
                    format_organization_id(value) for value in range(1, 102)
                ],
                operator_ctx=ctx,
            )

        selected = (
            await machine_organization_service.replace_machine_organization_access(
                client_id="confidential",
                dto=OAuth2ClientMachineOrganizationUpdateDTO(
                    machine_organization_access="selected",
                    organization_ids=[first_public, second_public],
                ),
                operator_ctx=ctx,
            )
        )
        assert set(selected.organization_ids) == {first_public, second_public}
        single = await machine_organization_service.replace_machine_organization_access(
            client_id="confidential",
            dto=OAuth2ClientMachineOrganizationUpdateDTO(
                machine_organization_access="single", organization_ids=[first_public]
            ),
            operator_ctx=ctx,
        )
        assert single.organization_ids == [first_public]
        cleared = (
            await machine_organization_service.replace_machine_organization_access(
                client_id="confidential",
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
                    client_id="confidential", dto=invalid, operator_ctx=ctx
                )
        with pytest.raises(InvalidOAuth2ClientPayloadError):
            await machine_organization_service.replace_machine_organization_access(
                client_id="confidential",
                dto=OAuth2ClientMachineOrganizationUpdateDTO(
                    machine_organization_access="selected",
                    organization_ids=[format_organization_id(999999999)],
                ),
                operator_ctx=ctx,
            )
        with pytest.raises(OAuth2ClientOrganizationAccessConflictError):
            await machine_organization_service.replace_machine_organization_access(
                client_id="public",
                dto=OAuth2ClientMachineOrganizationUpdateDTO(
                    machine_organization_access="unrestricted"
                ),
                operator_ctx=ctx,
            )
        await registry_service.delete_client(client_id="public", operator_ctx=ctx)
        with pytest.raises(OAuth2ClientAdminNotFoundError):
            await registry_service.delete_client(client_id="public", operator_ctx=ctx)
        with pytest.raises(OAuth2ClientAdminNotFoundError):
            await machine_organization_service._replace_machine_organizations(  # noqa: SLF001
                client_id="missing",
                organization_ids=[first_organization_id],
            )


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
            session_id=1,
            client_id="client",
            scopes=frozenset({"openid", "email", "profile"}),
        )
        response = await enabled.get_userinfo(principal_ctx=full)
        assert response["name"] == "Ada Lovelace"
        assert response["email"] == "oidc@example.test"
        subject_only = await enabled.get_userinfo(
            principal_ctx=OAuth2UserPrincipalContext(
                user_id=user.id,
                organization_id=organization_id,
                session_id=1,
                client_id="client",
                scopes=frozenset({"openid"}),
            )
        )
        assert set(subject_only) == {"sub"}

        with pytest.raises(OAuth2SessionInvalidError):
            await disabled.get_userinfo(principal_ctx=full)
        with pytest.raises(OIDCOpenIDScopeRequiredError):
            await enabled.get_userinfo(
                principal_ctx=OAuth2UserPrincipalContext(
                    user_id=user.id,
                    organization_id=organization_id,
                    session_id=1,
                    client_id="client",
                    scopes=frozenset({"profile"}),
                )
            )
        with pytest.raises(OAuth2SessionInvalidError):
            await enabled.get_userinfo(
                principal_ctx=OAuth2UserPrincipalContext(
                    user_id=999999,
                    organization_id=organization_id,
                    session_id=1,
                    client_id="client",
                    scopes=frozenset({"openid"}),
                )
            )

        user.is_active = False
        await session.flush()
        with pytest.raises(OAuth2SessionInvalidError):
            await enabled.get_userinfo(principal_ctx=full)
        user.is_active = True
        user_email = await session.scalar(
            select(UserEmailDB).where(UserEmailDB.user_id == user.id)
        )
        assert user_email is not None
        user_email.verified_at = None
        await session.flush()
        with pytest.raises(OAuth2SessionInvalidError):
            await enabled.get_userinfo(principal_ctx=full)
        user_email.verified_at = user.created_at
        user.first_name = ""
        user.last_name = ""
        await session.flush()
        minimal = await enabled.get_userinfo(principal_ctx=full)
        assert "name" not in minimal
        assert "given_name" not in minimal
        assert "family_name" not in minimal

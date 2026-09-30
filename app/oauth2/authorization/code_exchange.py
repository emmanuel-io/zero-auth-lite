"""Authorization code validation and token exchange."""

from datetime import datetime, UTC
from logging import getLogger
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.oauth2_authorization_code import OAuth2AuthorizationCodeDB
from app.identity.dtos import IdentityDTO, IdentityUserDTO
from app.oauth2.authorization.code import (
    hash_authorization_code,
    verify_s256_code_challenge,
)
from app.oauth2.authorization.dtos import (
    AuthorizationCodeReadDTO,
)
from app.oauth2.clients.auth import ClientAuth
from app.oauth2.clients.dtos import OAuth2ClientReadDTO
from app.oauth2.clients.user_organization_authorization import (
    ensure_client_allows_user_organization,
    OAuth2ClientNotAllowedForUserOrganizationError,
)
from app.oauth2.error_codes import OAuth2ErrorCode
from app.oauth2.errors import OAuth2InvalidGrantError, OAuth2ProtocolError
from app.oauth2.grants.request import AuthorizationCodeGrantRequest
from app.oauth2.grants.types import OAuth2GrantType, OAuth2SessionGrantType
from app.oauth2.oidc.claims import scope_includes_openid
from app.oauth2.oidc.id_tokens import create_id_token
from app.oauth2.schemas import OAuth2TokenResponse
from app.oauth2.settings import OAuth2Settings
from app.oauth2.tokens.access import (
    create_access_token_payload,
)
from app.oauth2.tokens.dtos import NewTokenSessionDTO
from app.oauth2.tokens.issuance import TokenIssuanceService
from app.oauth2.user_identity import load_eligible_oauth2_user_identity
from app.oauth2.validation import (
    client_allows_grant,
    should_issue_refresh_token,
    user_display_name,
    validate_oidc_scope_enabled,
    validate_requested_scope,
)


logger = getLogger(__name__)


def _validate_authorization_code_client(
    *, client_auth: ClientAuth | None, settings: OAuth2Settings
) -> OAuth2ClientReadDTO:
    """Validate the client against the current authorization-code policy."""
    if client_auth is None:
        raise OAuth2ProtocolError(error=OAuth2ErrorCode.INVALID_CLIENT)
    client = client_auth.client
    if not settings.is_grant_enabled(OAuth2GrantType.AUTHORIZATION_CODE):
        raise OAuth2ProtocolError(error=OAuth2ErrorCode.UNSUPPORTED_GRANT_TYPE)
    if not client.is_active:
        raise OAuth2ProtocolError(error=OAuth2ErrorCode.INVALID_CLIENT)
    if not client_allows_grant(client, OAuth2GrantType.AUTHORIZATION_CODE):
        raise OAuth2ProtocolError(error=OAuth2ErrorCode.UNAUTHORIZED_CLIENT)
    return client


async def _load_authorization_code(
    request: AuthorizationCodeGrantRequest,
    *,
    db_session: AsyncSession,
    settings: OAuth2Settings,
    client: OAuth2ClientReadDTO,
) -> tuple[str, AuthorizationCodeReadDTO]:
    """Load and validate the code binding, scope, lifetime, and PKCE proof."""
    client_id = client.client_id
    code_hash = hash_authorization_code(
        code=request.code,
        secret=settings.authorization_code_hash_secret.get_secret_value(),
    )
    code_row = await db_session.scalar(
        select(OAuth2AuthorizationCodeDB).where(
            OAuth2AuthorizationCodeDB.code_hash == code_hash
        )
    )
    authorization_code = (
        AuthorizationCodeReadDTO.model_validate(code_row)
        if code_row is not None
        else None
    )
    if authorization_code is None or authorization_code.used_at is not None:
        raise OAuth2InvalidGrantError
    if authorization_code.expires_at <= datetime.now(UTC):
        raise OAuth2InvalidGrantError
    if authorization_code.client_id != client_id:
        raise OAuth2InvalidGrantError
    if authorization_code.redirect_uri != request.redirect_uri:
        raise OAuth2InvalidGrantError
    try:
        validate_requested_scope(
            requested_scope=authorization_code.scope,
            allowed_scopes=client.scopes,
        )
        validate_oidc_scope_enabled(
            requested_scope=authorization_code.scope,
            oidc_enabled=settings.oidc_enabled,
        )
    except ValueError as exc:
        raise OAuth2ProtocolError(error=OAuth2ErrorCode.INVALID_SCOPE) from exc
    if authorization_code.code_challenge_method != "S256":
        raise OAuth2InvalidGrantError
    if not verify_s256_code_challenge(
        code_verifier=request.code_verifier,
        code_challenge=authorization_code.code_challenge,
    ):
        raise OAuth2InvalidGrantError
    return code_hash, authorization_code


async def _consume_authorization_code(
    *, db_session: AsyncSession, code_hash: str
) -> None:
    """Atomically mark an unused authorization code as consumed."""
    marked_row = await db_session.scalar(
        update(OAuth2AuthorizationCodeDB)
        .where(OAuth2AuthorizationCodeDB.code_hash == code_hash)
        .where(OAuth2AuthorizationCodeDB.used_at.is_(None))
        .values(used_at=datetime.now(UTC))
        .returning(OAuth2AuthorizationCodeDB.id)
    )
    await db_session.flush()
    if marked_row is None:
        raise OAuth2InvalidGrantError


async def _load_authorization_code_identity(
    *,
    db_session: AsyncSession,
    client: OAuth2ClientReadDTO,
    authorization_code: AuthorizationCodeReadDTO,
) -> IdentityDTO:
    """Load the eligible identity and enforce the client's organization policy."""
    identity = await load_eligible_oauth2_user_identity(
        db_session=db_session,
        user_id=authorization_code.user_id,
        organization_id=authorization_code.organization_id,
    )
    if identity is None:
        raise OAuth2InvalidGrantError
    try:
        await ensure_client_allows_user_organization(
            client=client,
            organization_id=authorization_code.organization_id,
            db_session=db_session,
        )
    except OAuth2ClientNotAllowedForUserOrganizationError as exc:
        raise OAuth2InvalidGrantError from exc
    return identity


async def _issue_authorization_code_tokens(  # noqa: PLR0913
    *,
    db_session: AsyncSession,
    settings: OAuth2Settings,
    signing_key: ed25519.Ed25519PrivateKey | str,
    client: OAuth2ClientReadDTO,
    authorization_code: AuthorizationCodeReadDTO,
    identity: IdentityDTO,
) -> OAuth2TokenResponse:
    """Persist a new token session and build its OAuth2/OIDC response."""
    client_id = client.client_id
    user, organization = identity.user, identity.organization
    token_issuance = TokenIssuanceService(
        db_session=db_session,
        settings=settings,
        signing_key=signing_key,
    )
    issued = await token_issuance.issue_new_session(
        NewTokenSessionDTO(
            access_payload=create_access_token_payload(
                user_public_id=user.public_id,
                organization_public_id=organization.public_id,
                audience=settings.access_token_audience,
                client_id=client_id,
                scope=authorization_code.scope,
            ),
            grant_type=OAuth2SessionGrantType.AUTHORIZATION_CODE,
            client_id=client_id,
            scope=authorization_code.scope,
            user_id=user.id,
            organization_id=organization.id,
            include_refresh_token=should_issue_refresh_token(
                settings=settings, client=client
            ),
        )
    )
    id_token = _create_id_token(
        authorization_code=authorization_code,
        client_id=client_id,
        user=user,
        key=signing_key,
        settings=settings,
    )
    logger.info(
        (
            "event=oauth2_token_issued outcome=attempted client_id=%s subject_id=%s "
            "organization_id=%s session_id=%s grant_type=authorization_code scope=%s"
        ),
        client_id,
        str(user.public_id),
        str(organization.public_id),
        str(issued.session_public_id),
        authorization_code.scope,
    )
    return token_issuance.build_response(issued.tokens, id_token=id_token)


# Code consumption and token issuance remain one ordered flow so their shared
# transaction and security checks can be audited together.
async def handle_authorization_code_grant(
    request: AuthorizationCodeGrantRequest,
    *,
    db_session: AsyncSession,
    settings: OAuth2Settings,
    client_auth: ClientAuth | None,
    signing_key: ed25519.Ed25519PrivateKey | str,
) -> OAuth2TokenResponse:
    """Consume one authorization code and issue its token response."""
    client = _validate_authorization_code_client(
        client_auth=client_auth,
        settings=settings,
    )
    code_hash, authorization_code = await _load_authorization_code(
        request,
        db_session=db_session,
        settings=settings,
        client=client,
    )
    await _consume_authorization_code(
        db_session=db_session,
        code_hash=code_hash,
    )
    identity = await _load_authorization_code_identity(
        db_session=db_session,
        client=client,
        authorization_code=authorization_code,
    )
    return await _issue_authorization_code_tokens(
        db_session=db_session,
        settings=settings,
        signing_key=signing_key,
        client=client,
        authorization_code=authorization_code,
        identity=identity,
    )


def _create_id_token(
    *,
    authorization_code: AuthorizationCodeReadDTO,
    client_id: UUID,
    user: IdentityUserDTO,
    key: ed25519.Ed25519PrivateKey | str,
    settings: OAuth2Settings,
) -> str | None:
    """Issue an ID token only when the authorization included OpenID scope."""
    if not scope_includes_openid(authorization_code.scope):
        return None
    requested_scopes = set(authorization_code.scope.split())
    return create_id_token(
        subject=str(user.public_id),
        audience=str(client_id),
        issuer=settings.issuer,
        lifetime_seconds=settings.id_token_lifetime_seconds,
        authenticated_at=authorization_code.authenticated_at,
        key=key,
        nonce=authorization_code.nonce,
        key_id=settings.signing_key_id,
        email=user.email if "email" in requested_scopes else None,
        email_verified=user.email_verified if "email" in requested_scopes else None,
        name=user_display_name(user) if "profile" in requested_scopes else None,
        given_name=user.first_name if "profile" in requested_scopes else None,
        family_name=user.last_name if "profile" in requested_scopes else None,
    )

"""Authorization code validation and token exchange."""

from datetime import datetime, UTC
from logging import getLogger

from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.oauth2_authorization_code import OAuth2AuthorizationCodeDB
from app.identity.dtos import IdentityUserDTO
from app.identity.public_ids import format_organization_id, format_user_id
from app.oauth2.authorization.code import (
    hash_authorization_code,
    verify_s256_code_challenge,
)
from app.oauth2.authorization.code_dtos import (
    AuthorizationCodeReadDTO,
)
from app.oauth2.clients.auth import ClientAuth
from app.oauth2.clients.user_organization_authorization import (
    ensure_client_allows_user_organization,
    OAuth2ClientNotAllowedForUserOrganizationError,
)
from app.oauth2.errors import OAuth2InvalidGrantError, OAuth2ProtocolError
from app.oauth2.grants.request import AuthorizationCodeGrantRequest
from app.oauth2.oidc.claims import scope_includes_openid
from app.oauth2.oidc.id_tokens import create_id_token
from app.oauth2.public_ids import format_oauth2_session_id
from app.oauth2.schemas import TokenPair
from app.oauth2.settings import OAuth2GrantType, OAuth2Settings
from app.oauth2.tokens.access import (
    create_access_token_payload,
)
from app.oauth2.tokens.dtos import NewTokenSessionDTO
from app.oauth2.tokens.issuance import TokenIssuanceService
from app.oauth2.user_identity import load_eligible_oauth2_user_identity
from app.oauth2.validation import (
    client_allows_grant,
    ERR_INVALID_CLIENT,
    ERR_INVALID_SCOPE,
    ERR_UNAUTHORIZED_CLIENT,
    ERR_UNSUPPORTED_GRANT_TYPE,
    should_issue_refresh_token,
    user_display_name,
    validate_oidc_scope_enabled,
    validate_requested_scope,
)


logger = getLogger(__name__)


# Code consumption and token issuance remain one ordered flow so their shared
# transaction and security checks can be audited together.
async def handle_authorization_code_grant(  # noqa: C901, PLR0912
    request: AuthorizationCodeGrantRequest,
    *,
    db_session: AsyncSession,
    settings: OAuth2Settings,
    client_auth: ClientAuth | None,
    signing_key: ed25519.Ed25519PrivateKey | str,
) -> TokenPair:
    """Consume one authorization code and issue its token response."""
    if client_auth is None:
        raise OAuth2ProtocolError(error=ERR_INVALID_CLIENT)
    client = client_auth.client
    if not settings.is_grant_enabled(OAuth2GrantType.authorization_code):
        raise OAuth2ProtocolError(error=ERR_UNSUPPORTED_GRANT_TYPE)
    if not client.is_active:
        raise OAuth2ProtocolError(error=ERR_INVALID_CLIENT)
    if not client_allows_grant(client, OAuth2GrantType.authorization_code):
        raise OAuth2ProtocolError(error=ERR_UNAUTHORIZED_CLIENT)
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
        raise OAuth2ProtocolError(error=ERR_INVALID_SCOPE) from exc
    if authorization_code.code_challenge_method != "S256":
        raise OAuth2InvalidGrantError
    if not verify_s256_code_challenge(
        code_verifier=request.code_verifier,
        code_challenge=authorization_code.code_challenge,
    ):
        raise OAuth2InvalidGrantError

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

    identity = await load_eligible_oauth2_user_identity(
        db_session=db_session,
        user_id=authorization_code.user_id,
        organization_id=authorization_code.organization_id,
    )
    if identity is None:
        raise OAuth2InvalidGrantError
    user, organization = identity.user, identity.organization
    try:
        await ensure_client_allows_user_organization(
            client=client,
            organization_id=authorization_code.organization_id,
            db_session=db_session,
        )
    except OAuth2ClientNotAllowedForUserOrganizationError as exc:
        raise OAuth2InvalidGrantError from exc

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
                audience=settings.jwt_audience,
                client_id=client_id,
                scope=authorization_code.scope,
            ),
            grant_type=OAuth2GrantType.authorization_code,
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
        format_user_id(user.public_id),
        format_organization_id(organization.public_id),
        format_oauth2_session_id(issued.session_public_id),
        authorization_code.scope,
    )
    return token_issuance.build_response(issued.token_pair, id_token=id_token)


def _create_id_token(
    *,
    authorization_code: AuthorizationCodeReadDTO,
    client_id: str,
    user: IdentityUserDTO,
    key: ed25519.Ed25519PrivateKey | str,
    settings: OAuth2Settings,
) -> str | None:
    """Issue an ID token only when the authorization included OpenID scope."""
    if not scope_includes_openid(authorization_code.scope):
        return None
    requested_scopes = set(authorization_code.scope.split())
    return create_id_token(
        subject=format_user_id(user.public_id),
        audience=client_id,
        jwt_issuer=settings.jwt_issuer,
        lifetime_seconds=settings.id_token_lifetime_seconds,
        authenticated_at=authorization_code.authenticated_at,
        key=key,
        nonce=authorization_code.nonce,
        key_id=settings.jwt_key_id,
        email=user.email if "email" in requested_scopes else None,
        email_verified=user.email_verified if "email" in requested_scopes else None,
        name=user_display_name(user) if "profile" in requested_scopes else None,
        given_name=user.first_name if "profile" in requested_scopes else None,
        family_name=user.last_name if "profile" in requested_scopes else None,
    )

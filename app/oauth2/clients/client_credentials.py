"""Client credentials OAuth2 workflow."""

from logging import getLogger

from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy.ext.asyncio import AsyncSession

from app.oauth2.clients.auth import ClientAuth
from app.oauth2.error_codes import OAuth2ErrorCode
from app.oauth2.errors import OAuth2ProtocolError
from app.oauth2.grants.request import ClientCredentialsGrantRequest
from app.oauth2.grants.types import OAuth2GrantType, OAuth2SessionGrantType
from app.oauth2.schemas import OAuth2TokenResponse
from app.oauth2.settings import OAuth2Settings
from app.oauth2.tokens.access import (
    create_client_access_token_payload,
)
from app.oauth2.tokens.dtos import NewTokenSessionDTO
from app.oauth2.tokens.issuance import TokenIssuanceService
from app.oauth2.validation import (
    client_allows_grant,
    normalize_scope,
    validate_oidc_scope_enabled,
    validate_requested_scope,
)


logger = getLogger(__name__)


async def handle_client_credentials_grant(
    request: ClientCredentialsGrantRequest,
    *,
    db_session: AsyncSession,
    settings: OAuth2Settings,
    client_auth: ClientAuth | None,
    signing_key: ed25519.Ed25519PrivateKey | str,
) -> OAuth2TokenResponse:
    """Issue a machine access token for an authenticated confidential client."""
    if client_auth is None:
        raise OAuth2ProtocolError(error=OAuth2ErrorCode.INVALID_CLIENT)
    client = client_auth.client
    client_id = client.client_id
    if not settings.is_grant_enabled(OAuth2GrantType.CLIENT_CREDENTIALS):
        raise OAuth2ProtocolError(error=OAuth2ErrorCode.UNSUPPORTED_GRANT_TYPE)
    if not client.is_active:
        raise OAuth2ProtocolError(error=OAuth2ErrorCode.INVALID_CLIENT)
    if not client.is_confidential:
        raise OAuth2ProtocolError(error=OAuth2ErrorCode.INVALID_CLIENT)
    if not client_allows_grant(client, OAuth2GrantType.CLIENT_CREDENTIALS):
        raise OAuth2ProtocolError(error=OAuth2ErrorCode.UNAUTHORIZED_CLIENT)

    requested_scope = normalize_scope(request.scope)
    try:
        validate_requested_scope(
            requested_scope=requested_scope,
            allowed_scopes=client.scopes,
        )
        validate_oidc_scope_enabled(
            requested_scope=requested_scope,
            oidc_enabled=False,
        )
    except ValueError as exc:
        raise OAuth2ProtocolError(error=OAuth2ErrorCode.INVALID_SCOPE) from exc

    token_issuance = TokenIssuanceService(
        db_session=db_session,
        settings=settings,
        signing_key=signing_key,
    )
    issued = await token_issuance.issue_new_session(
        NewTokenSessionDTO(
            access_payload=create_client_access_token_payload(
                client_id=client_id,
                audience=settings.access_token_audience,
                scope=requested_scope,
            ),
            grant_type=OAuth2SessionGrantType.CLIENT_CREDENTIALS,
            client_id=client_id,
            scope=requested_scope,
            user_id=None,
            organization_id=None,
            include_refresh_token=False,
        )
    )
    logger.info(
        (
            "event=oauth2_token_issued outcome=attempted client_id=%s session_id=%s "
            "grant_type=client_credentials scope=%s"
        ),
        client_id,
        str(issued.session_public_id),
        requested_scope,
    )
    return token_issuance.build_response(issued.tokens)

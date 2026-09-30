"""Browser authorization requests for the authorization code flow."""

from dataclasses import dataclass
from datetime import datetime, UTC
from logging import getLogger
from urllib.parse import urlencode

from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.oauth2_authorization_code import OAuth2AuthorizationCodeDB
from app.db.models.oauth2_client import OAuth2ClientDB
from app.identifiers import parse_uuid4
from app.oauth2.authorization.code import (
    create_authorization_code,
    hash_authorization_code,
)
from app.oauth2.authorization.dtos import (
    AuthorizationCodeCreateDTO,
)
from app.oauth2.authorization.result import (
    AuthorizationConsentPage,
    AuthorizationRedirect,
    AuthorizationResult,
)
from app.oauth2.clients.dtos import OAuth2ClientReadDTO
from app.oauth2.clients.user_organization_authorization import (
    ensure_client_allows_user_organization,
    OAuth2ClientNotAllowedForUserOrganizationError,
)
from app.oauth2.error_codes import OAuth2ErrorCode
from app.oauth2.grants.types import OAuth2GrantType
from app.oauth2.settings import OAuth2Settings
from app.oauth2.validation import (
    client_allows_grant,
    normalize_scope,
    reject_redirect_uri_fragment,
    validate_oidc_scope_enabled,
    validate_pkce_challenge,
    validate_pkce_method,
    validate_requested_scope,
)
from app.security.principals import InteractiveUserPrincipalContext


logger = getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AuthorizationRequestInput:
    """Client-controlled OAuth2 authorization input awaiting validation."""

    response_type: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    scope: str | None = None
    state: str | None = None
    nonce: str | None = None


@dataclass(frozen=True, slots=True)
class ValidatedAuthorizationRequest:
    """Authorization request state trusted before browser interaction."""

    request: AuthorizationRequestInput
    client: OAuth2ClientReadDTO
    requested_scope: str


def _authorization_error_redirect(
    *,
    redirect_uri: str,
    error: OAuth2ErrorCode,
    state: str | None,
) -> AuthorizationRedirect:
    """Build a redirect error only after the callback URI is trusted."""
    query: dict[str, str] = {"error": error.value}
    if state is not None:
        query["state"] = state
    separator = "&" if "?" in redirect_uri else "?"
    return AuthorizationRedirect(url=f"{redirect_uri}{separator}{urlencode(query)}")


class AuthorizationRequestService:
    """Validate browser authorization requests and issue one-time codes."""

    def __init__(
        self,
        *,
        settings: OAuth2Settings,
        db_session: AsyncSession,
    ) -> None:
        """Store the dependencies required for browser authorization."""
        self.settings = settings
        self.db_session = db_session

    async def validate_request(
        self,
        request: AuthorizationRequestInput,
    ) -> ValidatedAuthorizationRequest | AuthorizationRedirect:
        """Validate client-controlled authorization input before interaction."""
        redirect_uri = request.redirect_uri
        reject_redirect_uri_fragment(redirect_uri)

        try:
            parsed_client_id = parse_uuid4(request.client_id)
        except ValueError as exc:
            raise ValueError(OAuth2ErrorCode.INVALID_CLIENT) from exc
        client_row = await self.db_session.scalar(
            select(OAuth2ClientDB).where(OAuth2ClientDB.client_id == parsed_client_id)
        )
        client = (
            OAuth2ClientReadDTO.model_validate(client_row)
            if client_row is not None
            else None
        )
        if client is None or not client.is_active:
            raise ValueError(OAuth2ErrorCode.INVALID_CLIENT)
        if redirect_uri not in (client.redirect_uris or []):
            raise ValueError(OAuth2ErrorCode.INVALID_REQUEST)
        if not self.settings.is_grant_enabled(OAuth2GrantType.AUTHORIZATION_CODE):
            return _authorization_error_redirect(
                redirect_uri=redirect_uri,
                error=OAuth2ErrorCode.UNSUPPORTED_RESPONSE_TYPE,
                state=request.state,
            )
        if request.response_type != "code":
            return _authorization_error_redirect(
                redirect_uri=redirect_uri,
                error=OAuth2ErrorCode.UNSUPPORTED_RESPONSE_TYPE,
                state=request.state,
            )
        if not client_allows_grant(client, OAuth2GrantType.AUTHORIZATION_CODE):
            return _authorization_error_redirect(
                redirect_uri=redirect_uri,
                error=OAuth2ErrorCode.UNAUTHORIZED_CLIENT,
                state=request.state,
            )
        try:
            validate_pkce_method(request.code_challenge_method)
            validate_pkce_challenge(request.code_challenge)
        except ValueError:
            return _authorization_error_redirect(
                redirect_uri=redirect_uri,
                error=OAuth2ErrorCode.INVALID_REQUEST,
                state=request.state,
            )
        requested_scope = normalize_scope(request.scope)
        try:
            validate_requested_scope(
                requested_scope=requested_scope,
                allowed_scopes=client.scopes,
            )
            validate_oidc_scope_enabled(
                requested_scope=requested_scope,
                oidc_enabled=self.settings.oidc_enabled,
            )
        except ValueError:
            return _authorization_error_redirect(
                redirect_uri=redirect_uri,
                error=OAuth2ErrorCode.INVALID_SCOPE,
                state=request.state,
            )
        return ValidatedAuthorizationRequest(
            request=request,
            client=client,
            requested_scope=requested_scope,
        )

    async def authorize_validated(
        self,
        *,
        user_ctx: InteractiveUserPrincipalContext,
        validated: ValidatedAuthorizationRequest,
        consent: str | None = None,
    ) -> AuthorizationResult:
        """Apply user authorization policy to trusted request state."""
        request = validated.request
        client = validated.client
        redirect_uri = request.redirect_uri
        requested_scope = validated.requested_scope
        try:
            await ensure_client_allows_user_organization(
                client=client,
                organization_id=user_ctx.organization_id,
                db_session=self.db_session,
            )
        except OAuth2ClientNotAllowedForUserOrganizationError:
            return _authorization_error_redirect(
                redirect_uri=redirect_uri,
                error=OAuth2ErrorCode.ACCESS_DENIED,
                state=request.state,
            )
        if client.requires_consent:
            if consent == "deny":
                return _authorization_error_redirect(
                    redirect_uri=redirect_uri,
                    error=OAuth2ErrorCode.ACCESS_DENIED,
                    state=request.state,
                )
            if consent != "approve":
                return AuthorizationConsentPage(
                    client_name=client.name,
                    requested_scope=requested_scope,
                )

        raw_code = create_authorization_code()
        authenticated_at = user_ctx.authenticated_at or datetime.now(UTC)
        code_hash = hash_authorization_code(
            code=raw_code,
            secret=self.settings.authorization_code_hash_secret.get_secret_value(),
        )
        data = AuthorizationCodeCreateDTO(
            code_hash=code_hash,
            client_id=client.client_id,
            redirect_uri=redirect_uri,
            scope=requested_scope,
            nonce=request.nonce,
            code_challenge=request.code_challenge,
            code_challenge_method="S256",
            expires_at=datetime.now(UTC) + self.settings.authorization_code_ttl_delta,
            authenticated_at=authenticated_at,
            user_id=user_ctx.user_id,
            organization_id=user_ctx.organization_id,
        )
        await self.db_session.execute(
            insert(OAuth2AuthorizationCodeDB).values(**data.model_dump())
        )
        await self.db_session.flush()
        logger.info(
            (
                "event=oauth2_authorization_code outcome=attempted client_id=%s "
                "subject_id=%s organization_id=%s scope=%s"
            ),
            client.client_id,
            str(user_ctx.user_public_id) if user_ctx.user_public_id else "unknown",
            str(user_ctx.organization_public_id)
            if user_ctx.organization_public_id
            else "unknown",
            requested_scope,
        )
        query = {"code": raw_code}
        if request.state is not None:
            query["state"] = request.state
        separator = "&" if "?" in redirect_uri else "?"
        return AuthorizationRedirect(url=f"{redirect_uri}{separator}{urlencode(query)}")

    def deny_interaction(
        self,
        validated: ValidatedAuthorizationRequest,
    ) -> AuthorizationRedirect:
        """Return a protocol denial when no browser interaction is available."""
        request = validated.request
        return _authorization_error_redirect(
            redirect_uri=request.redirect_uri,
            error=OAuth2ErrorCode.ACCESS_DENIED,
            state=request.state,
        )

    # Keep the OAuth2 request fields visible throughout authorization.
    async def authorize_code(  # noqa: PLR0913
        self,
        *,
        user_ctx: InteractiveUserPrincipalContext,
        response_type: str,
        client_id: str,
        redirect_uri: str | None,
        scope: str | None,
        state: str | None,
        code_challenge: str | None,
        code_challenge_method: str | None,
        nonce: str | None = None,
        consent: str | None = None,
    ) -> AuthorizationResult:
        """Authorize an OAuth2 client and issue an authorization code.

        Raises:
            ValueError: If the request is invalid.
        """
        if redirect_uri is None or code_challenge is None:
            raise ValueError(OAuth2ErrorCode.INVALID_REQUEST)
        request = AuthorizationRequestInput(
            response_type=response_type,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method or "",
        )
        validated = await self.validate_request(request)
        if isinstance(validated, AuthorizationRedirect):
            return validated
        return await self.authorize_validated(
            user_ctx=user_ctx,
            validated=validated,
            consent=consent,
        )

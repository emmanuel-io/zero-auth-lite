# ruff: noqa: PLR0913
"""Browser authorization requests for the authorization code flow."""

from dataclasses import dataclass
from datetime import datetime, UTC
from logging import getLogger
from urllib.parse import urlencode, urlsplit

from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.oauth2_authorization_code import OAuth2AuthorizationCodeDB
from app.db.models.oauth2_client import OAuth2ClientDB
from app.identity.public_ids import format_organization_id, format_user_id
from app.oauth2.authorization.code import (
    create_authorization_code,
    hash_authorization_code,
)
from app.oauth2.authorization.code_dtos import (
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
from app.oauth2.settings import OAuth2GrantType, OAuth2Settings
from app.oauth2.validation import (
    client_allows_grant,
    ERR_INVALID_CLIENT,
    ERR_INVALID_REQUEST,
    ERR_UNAUTHORIZED_CLIENT,
    ERR_UNSUPPORTED_RESPONSE_TYPE,
    normalize_scope,
    validate_oidc_scope_enabled,
    validate_pkce_challenge,
    validate_pkce_method,
    validate_redirect_uri,
    validate_requested_scope,
)
from app.security.dtos import InteractiveUserPrincipalContext


logger = getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    """Validated OAuth2 authorization request payload."""

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

    request: AuthorizationRequest
    client: OAuth2ClientReadDTO
    requested_scope: str


def validate_redirect_uri_text(redirect_uri: str) -> None:
    """Reject redirect URIs carrying fragments."""
    if urlsplit(redirect_uri).fragment:
        raise ValueError(ERR_INVALID_REQUEST)


def _authorization_error_redirect(
    *,
    redirect_uri: str,
    error: str,
    state: str | None,
) -> AuthorizationRedirect:
    """Build a redirect error only after the callback URI is trusted."""
    query = {"error": error}
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
        request: AuthorizationRequest,
    ) -> ValidatedAuthorizationRequest | AuthorizationRedirect:
        """Validate client-controlled authorization input before interaction."""
        redirect_uri = request.redirect_uri
        validate_redirect_uri_text(redirect_uri)
        validate_redirect_uri(redirect_uri)

        client_row = await self.db_session.scalar(
            select(OAuth2ClientDB).where(OAuth2ClientDB.client_id == request.client_id)
        )
        client = (
            OAuth2ClientReadDTO.model_validate(client_row)
            if client_row is not None
            else None
        )
        if client is None or not client.is_active:
            raise ValueError(ERR_INVALID_CLIENT)
        if redirect_uri not in (client.redirect_uris or []):
            raise ValueError(ERR_INVALID_REQUEST)
        if not self.settings.is_grant_enabled(OAuth2GrantType.authorization_code):
            return _authorization_error_redirect(
                redirect_uri=redirect_uri,
                error=ERR_UNSUPPORTED_RESPONSE_TYPE,
                state=request.state,
            )
        if request.response_type != "code":
            return _authorization_error_redirect(
                redirect_uri=redirect_uri,
                error=ERR_UNSUPPORTED_RESPONSE_TYPE,
                state=request.state,
            )
        if not client_allows_grant(client, OAuth2GrantType.authorization_code):
            return _authorization_error_redirect(
                redirect_uri=redirect_uri,
                error=ERR_UNAUTHORIZED_CLIENT,
                state=request.state,
            )
        try:
            validate_pkce_method(request.code_challenge_method)
            validate_pkce_challenge(request.code_challenge)
        except ValueError:
            return _authorization_error_redirect(
                redirect_uri=redirect_uri,
                error=ERR_INVALID_REQUEST,
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
                error="invalid_scope",
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
                error="access_denied",
                state=request.state,
            )
        if client.requires_consent:
            if consent == "deny":
                return _authorization_error_redirect(
                    redirect_uri=redirect_uri,
                    error="access_denied",
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
            client_id=request.client_id,
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
            request.client_id,
            format_user_id(user_ctx.user_public_id)
            if user_ctx.user_public_id
            else "unknown",
            format_organization_id(user_ctx.organization_public_id)
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
            error="access_denied",
            state=request.state,
        )

    async def authorize_code(
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

        Args:
            user_ctx: Authenticated browser user context.
            response_type (str): OAuth2 response type.
            client_id (str): OAuth2 client identifier.
            redirect_uri (str | None): Requested redirect URI.
            scope (str | None): Requested scope string.
            state (str | None): Client state value.
            code_challenge (str | None): PKCE S256 challenge.
            code_challenge_method (str | None): PKCE challenge method.
            nonce (str | None): Optional OIDC nonce bound into the auth code.
            consent (str | None): Optional user consent decision.

        Returns:
            AuthorizationResult: Consent page data or client callback redirect.

        Raises:
            ValueError: If the request is invalid.
        """
        if redirect_uri is None or code_challenge is None:
            raise ValueError(ERR_INVALID_REQUEST)
        request = AuthorizationRequest(
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

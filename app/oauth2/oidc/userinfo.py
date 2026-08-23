"""OIDC UserInfo service implementation."""

from sqlalchemy.ext.asyncio import AsyncSession

from app.identity.public_ids import format_user_id
from app.oauth2.errors import OAuth2SessionInvalidError, OIDCOpenIDScopeRequiredError
from app.oauth2.oidc.schemas import UserInfoResponse
from app.oauth2.settings import OAuth2Settings
from app.oauth2.user_identity import load_eligible_oauth2_user_identity
from app.oauth2.validation import user_display_name
from app.security.dtos import OAuth2UserPrincipalContext


class OIDCUserInfoService:
    """Return OIDC UserInfo claims for validated OAuth2 principals."""

    def __init__(
        self,
        *,
        db_session: AsyncSession,
        settings: OAuth2Settings,
    ) -> None:
        """Store the focused dependencies needed for UserInfo."""
        self.db_session = db_session
        self.settings = settings

    async def get_userinfo(
        self,
        *,
        principal_ctx: OAuth2UserPrincipalContext,
    ) -> UserInfoResponse:
        """Return OIDC userinfo for a validated user principal."""
        if not self.settings.oidc_enabled:
            raise OAuth2SessionInvalidError
        if "openid" not in principal_ctx.scopes:
            raise OIDCOpenIDScopeRequiredError
        identity = await load_eligible_oauth2_user_identity(
            db_session=self.db_session,
            user_id=principal_ctx.user_id,
            organization_id=principal_ctx.organization_id,
        )
        if identity is None:
            raise OAuth2SessionInvalidError
        user = identity.user

        response: UserInfoResponse = {"sub": format_user_id(user.public_id)}
        if "email" in principal_ctx.scopes:
            response["email"] = user.email
            response["email_verified"] = user.email_verified
        if "profile" in principal_ctx.scopes:
            display_name = user_display_name(user)
            if display_name is not None:
                response["name"] = display_name
            if user.first_name:
                response["given_name"] = user.first_name
            if user.last_name:
                response["family_name"] = user.last_name
        return response

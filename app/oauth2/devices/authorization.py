"""Device authorization creation and browser verification services."""

from dataclasses import asdict
from datetime import datetime, timedelta, UTC
from logging import getLogger
from typing import cast, TYPE_CHECKING
from urllib.parse import urlencode

from sqlalchemy import insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.oauth2_client import OAuth2ClientDB
from app.db.models.oauth2_device_authorization import OAuth2DeviceAuthorizationDB
from app.oauth2.clients.dtos import OAuth2ClientReadDTO
from app.oauth2.clients.user_organization_authorization import (
    ensure_client_allows_user_organization,
    OAuth2ClientNotAllowedForUserOrganizationError,
)
from app.oauth2.devices.authorization_codes import (
    create_device_code,
    create_user_code,
)
from app.oauth2.devices.dtos import (
    DeviceAuthorizationCreateDTO,
    DeviceAuthorizationReadDTO,
    DeviceInteractionDTO,
)
from app.oauth2.devices.mapping import to_device_authorization_dto
from app.oauth2.error_codes import OAuth2ErrorCode
from app.oauth2.errors import OAuth2ProtocolError
from app.oauth2.grants.types import OAuth2GrantType
from app.oauth2.schemas import DeviceAuthorizationResponse
from app.oauth2.settings import OAuth2Settings
from app.oauth2.tokens.hash import hash_oauth2_token
from app.oauth2.validation import (
    client_allows_grant,
    normalize_scope,
    normalize_user_code,
    validate_oidc_scope_enabled,
    validate_requested_scope,
)
from app.security.principals import UserPrincipalContext


if TYPE_CHECKING:
    from sqlalchemy.engine import CursorResult


logger = getLogger(__name__)


def _is_user_code_collision(exc: IntegrityError) -> bool:
    """Identify the SQLite unique-index failure that is safe to retry."""
    return "oauth2_device_authorization.user_code_hash" in str(exc.orig)


class DeviceAuthorizationService:
    """Handle device authorization setup and signed-in user decisions."""

    def __init__(
        self,
        *,
        settings: OAuth2Settings,
        db_session: AsyncSession,
    ) -> None:
        """Store the dependencies required for device authorization."""
        self.settings = settings
        self.db_session = db_session

    async def create_device_authorization(
        self,
        *,
        client: OAuth2ClientReadDTO,
        scope: str | None,
        verification_uri: str,
    ) -> DeviceAuthorizationResponse:
        """Create an OAuth2 device authorization request."""
        if not self.settings.is_grant_enabled(OAuth2GrantType.DEVICE_CODE):
            raise OAuth2ProtocolError(error=OAuth2ErrorCode.UNSUPPORTED_GRANT_TYPE)
        if not client.is_active:
            raise OAuth2ProtocolError(error=OAuth2ErrorCode.UNAUTHORIZED_CLIENT)
        if not client_allows_grant(client, OAuth2GrantType.DEVICE_CODE):
            raise OAuth2ProtocolError(error=OAuth2ErrorCode.UNAUTHORIZED_CLIENT)

        client_id = client.client_id

        requested_scope = normalize_scope(scope)
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

        expires_at = datetime.now(UTC) + timedelta(
            seconds=self.settings.device_code_lifetime_seconds
        )
        token_hash_secret = self.settings.token_hash_secret.get_secret_value()
        for _attempt in range(self.settings.device_code_create_attempts):
            device_code = create_device_code()
            user_code = create_user_code()
            user_code_hash = hash_oauth2_token(
                token=normalize_user_code(user_code),
                secret=token_hash_secret,
            )
            data = DeviceAuthorizationCreateDTO(
                device_code_hash=hash_oauth2_token(
                    token=device_code,
                    secret=token_hash_secret,
                ),
                user_code_hash=user_code_hash,
                client_id=client_id,
                scope=requested_scope,
                expires_at=expires_at,
                interval_seconds=self.settings.device_code_interval_seconds,
                organization_id=None,
            )
            try:
                async with self.db_session.begin_nested():
                    await self.db_session.execute(
                        insert(OAuth2DeviceAuthorizationDB).values(**asdict(data))
                    )
                    await self.db_session.flush()
            except IntegrityError as exc:
                if not _is_user_code_collision(exc):
                    raise
            else:
                break
        else:
            msg = "Unable to generate a unique device user code"
            raise RuntimeError(msg)

        logger.info(
            "OAuth2 device authorization created client_id=%s scope=%s expires_at=%s",
            client_id,
            requested_scope,
            expires_at.isoformat(),
        )
        return DeviceAuthorizationResponse(
            device_code=device_code,
            user_code=user_code,
            verification_uri=verification_uri,
            verification_uri_complete=(
                f"{verification_uri}?{urlencode({'user_code': user_code})}"
            ),
            expires_in=self.settings.device_code_lifetime_seconds,
            interval=self.settings.device_code_interval_seconds,
        )

    async def _pending_authorization(
        self, *, code_hash: str
    ) -> DeviceAuthorizationReadDTO | None:
        """Load one live Device Code interaction without exposing its state."""
        row = await self.db_session.scalar(
            select(OAuth2DeviceAuthorizationDB)
            .where(OAuth2DeviceAuthorizationDB.user_code_hash == code_hash)
            .where(OAuth2DeviceAuthorizationDB.expires_at > datetime.now(UTC))
            .where(OAuth2DeviceAuthorizationDB.approved_at.is_(None))
            .where(OAuth2DeviceAuthorizationDB.denied_at.is_(None))
            .where(OAuth2DeviceAuthorizationDB.used_at.is_(None))
        )
        return to_device_authorization_dto(row) if row is not None else None

    async def _allowed_interaction_client(
        self,
        *,
        authorization: DeviceAuthorizationReadDTO,
        user_ctx: UserPrincipalContext,
    ) -> OAuth2ClientReadDTO | None:
        """Validate the client, scope, and organization at interaction time."""
        row = await self.db_session.scalar(
            select(OAuth2ClientDB).where(
                OAuth2ClientDB.client_id == authorization.client_id
            )
        )
        client = OAuth2ClientReadDTO.model_validate(row) if row is not None else None
        if (
            client is None
            or not client.is_active
            or not client_allows_grant(client, OAuth2GrantType.DEVICE_CODE)
        ):
            return None
        try:
            validate_requested_scope(
                requested_scope=authorization.scope,
                allowed_scopes=client.scopes,
            )
            await ensure_client_allows_user_organization(
                client=client,
                organization_id=user_ctx.organization_id,
                db_session=self.db_session,
            )
        except (ValueError, OAuth2ClientNotAllowedForUserOrganizationError):
            return None
        return client

    async def decide_device_authorization(
        self,
        *,
        user_ctx: UserPrincipalContext,
        user_code: str,
        approve: bool,
    ) -> bool:
        """Approve or deny a valid Device Code interaction exactly once."""
        code_hash = hash_oauth2_token(
            token=normalize_user_code(user_code),
            secret=self.settings.token_hash_secret.get_secret_value(),
        )
        authorization = await self._pending_authorization(code_hash=code_hash)
        if (
            authorization is None
            or await self._allowed_interaction_client(
                authorization=authorization,
                user_ctx=user_ctx,
            )
            is None
        ):
            return False
        now = datetime.now(UTC)
        result = await self.db_session.execute(
            update(OAuth2DeviceAuthorizationDB)
            .where(OAuth2DeviceAuthorizationDB.user_code_hash == code_hash)
            .where(OAuth2DeviceAuthorizationDB.expires_at > now)
            .where(OAuth2DeviceAuthorizationDB.approved_at.is_(None))
            .where(OAuth2DeviceAuthorizationDB.denied_at.is_(None))
            .where(OAuth2DeviceAuthorizationDB.used_at.is_(None))
            .values(
                user_id=user_ctx.user_id,
                organization_id=user_ctx.organization_id,
                approved_at=now if approve else None,
                denied_at=None if approve else now,
            )
            .execution_options(synchronize_session=False)
        )
        await self.db_session.flush()
        decided = bool(cast("CursorResult[object]", result).rowcount)
        if decided:
            logger.info(
                (
                    "event=oauth2_device_authorization outcome=attempted "
                    "decision=%s subject_id=%s organization_id=%s"
                ),
                "approved" if approve else "denied",
                str(user_ctx.user_public_id) if user_ctx.user_public_id else "unknown",
                str(user_ctx.organization_public_id)
                if user_ctx.organization_public_id
                else "unknown",
            )
        return decided

    async def get_device_interaction(
        self,
        *,
        user_ctx: UserPrincipalContext,
        user_code: str,
    ) -> DeviceInteractionDTO | None:
        """Return safe details for one live device interaction."""
        code_hash = hash_oauth2_token(
            token=normalize_user_code(user_code),
            secret=self.settings.token_hash_secret.get_secret_value(),
        )
        authorization = await self._pending_authorization(code_hash=code_hash)
        if authorization is None:
            return None
        client = await self._allowed_interaction_client(
            authorization=authorization,
            user_ctx=user_ctx,
        )
        if client is None:
            return None
        return DeviceInteractionDTO(
            client_name=client.name,
            scopes=tuple(authorization.scope.split()),
        )

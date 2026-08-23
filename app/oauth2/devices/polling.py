"""Device-code polling and token issuance workflow."""

from dataclasses import dataclass
from datetime import datetime, UTC
from enum import StrEnum
from logging import getLogger
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.dependencies import independent_transaction
from app.db.models.oauth2_device_authorization import OAuth2DeviceAuthorizationDB
from app.identity.public_ids import format_organization_id, format_user_id
from app.oauth2.clients.auth import ClientAuth, lock_and_reload_token_client
from app.oauth2.clients.user_organization_authorization import (
    ensure_client_allows_user_organization,
    OAuth2ClientNotAllowedForUserOrganizationError,
)
from app.oauth2.devices.dtos import DeviceAuthorizationReadDTO
from app.oauth2.devices.mapping import to_device_authorization_dto
from app.oauth2.errors import (
    OAuth2AuthorizationPendingError,
    OAuth2InvalidGrantError,
    OAuth2ProtocolError,
    OAuth2SlowDownError,
)
from app.oauth2.grants.request import DeviceCodeGrantRequest
from app.oauth2.public_ids import format_oauth2_session_id
from app.oauth2.schemas import TokenPair
from app.oauth2.settings import OAuth2GrantType, OAuth2Settings
from app.oauth2.tokens.access import (
    create_access_token_payload,
)
from app.oauth2.tokens.dtos import NewTokenSessionDTO
from app.oauth2.tokens.hash import hash_oauth2_token
from app.oauth2.tokens.issuance import TokenIssuanceService
from app.oauth2.user_identity import load_eligible_oauth2_user_identity
from app.oauth2.validation import (
    client_allows_grant,
    ERR_INVALID_SCOPE,
    ERR_UNAUTHORIZED_CLIENT,
    ERR_UNSUPPORTED_GRANT_TYPE,
    should_issue_refresh_token,
    validate_oidc_scope_enabled,
    validate_requested_scope,
)


logger = getLogger(__name__)


if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import async_sessionmaker


class DevicePollStatus(StrEnum):
    """Result of atomically evaluating one device-code poll."""

    APPROVED = "approved"
    PENDING = "pending"
    SLOW_DOWN = "slow_down"
    DENIED = "denied"
    EXPIRED = "expired"
    INVALID = "invalid"


@dataclass(frozen=True, slots=True)
class DevicePollDecision:
    """Polling outcome and approved authorization snapshot, when available."""

    status: DevicePollStatus
    authorization: DeviceAuthorizationReadDTO | None = None


async def evaluate_device_poll(  # noqa: PLR0911
    *,
    session_factory: "async_sessionmaker[AsyncSession]",
    device_code_hash: str,
    client_id: str,
    now: datetime,
) -> DevicePollDecision:
    """Evaluate polling and persist pending/slow-down state independently."""
    async with independent_transaction(session_factory) as db_session:
        authorization_row = await db_session.scalar(
            select(OAuth2DeviceAuthorizationDB).where(
                OAuth2DeviceAuthorizationDB.device_code_hash == device_code_hash
            )
        )
        authorization = (
            to_device_authorization_dto(authorization_row)
            if authorization_row is not None
            else None
        )
        if authorization is None or authorization.client_id != client_id:
            return DevicePollDecision(DevicePollStatus.INVALID)
        if authorization.expires_at <= now:
            return DevicePollDecision(DevicePollStatus.EXPIRED)
        if authorization.denied_at is not None:
            return DevicePollDecision(DevicePollStatus.DENIED)
        if authorization.used_at is not None:
            return DevicePollDecision(DevicePollStatus.INVALID)
        if authorization.last_polled_at is not None:
            last_polled_at = authorization.last_polled_at
            if (now - last_polled_at).total_seconds() < authorization.interval_seconds:
                await db_session.execute(
                    update(OAuth2DeviceAuthorizationDB)
                    .where(
                        OAuth2DeviceAuthorizationDB.device_code_hash == device_code_hash
                    )
                    .values(
                        last_polled_at=now,
                        interval_seconds=(
                            OAuth2DeviceAuthorizationDB.interval_seconds + 5
                        ),
                    )
                    .execution_options(synchronize_session=False)
                )
                return DevicePollDecision(DevicePollStatus.SLOW_DOWN)
        if authorization.approved_at is None or authorization.user_id is None:
            await db_session.execute(
                update(OAuth2DeviceAuthorizationDB)
                .where(OAuth2DeviceAuthorizationDB.device_code_hash == device_code_hash)
                .values(last_polled_at=now)
                .execution_options(synchronize_session=False)
            )
            return DevicePollDecision(DevicePollStatus.PENDING)
        return DevicePollDecision(DevicePollStatus.APPROVED, authorization)


# The polling state machine stays ordered here so each terminal and retry state
# is visible before the authorization is consumed.
async def handle_device_code_grant(  # noqa: C901, PLR0912, PLR0913
    request: DeviceCodeGrantRequest,
    *,
    db_session: AsyncSession,
    session_factory: "async_sessionmaker[AsyncSession]",
    settings: OAuth2Settings,
    client_auth: ClientAuth | None,
    signing_key: ed25519.Ed25519PrivateKey | str,
) -> TokenPair:
    """Exchange an approved OAuth2 device code for a token pair."""
    if not settings.is_grant_enabled(OAuth2GrantType.device_code):
        raise OAuth2ProtocolError(error=ERR_UNSUPPORTED_GRANT_TYPE)
    if client_auth is None:
        raise OAuth2ProtocolError(error="invalid_client")
    client = client_auth.client
    client_id = client.client_id
    if not client.is_active:
        raise OAuth2ProtocolError(error="invalid_client")
    now = datetime.now(UTC)
    device_code_hash = hash_oauth2_token(
        token=request.device_code,
        secret=settings.token_hash_secret.get_secret_value(),
    )
    decision = await evaluate_device_poll(
        session_factory=session_factory,
        device_code_hash=device_code_hash,
        client_id=client_id,
        now=now,
    )
    if decision.status == DevicePollStatus.PENDING:
        raise OAuth2AuthorizationPendingError
    if decision.status == DevicePollStatus.SLOW_DOWN:
        raise OAuth2SlowDownError
    if decision.status == DevicePollStatus.DENIED:
        raise OAuth2ProtocolError(error="access_denied")
    if decision.status == DevicePollStatus.EXPIRED:
        raise OAuth2ProtocolError(error="expired_token")
    if decision.status == DevicePollStatus.INVALID or decision.authorization is None:
        raise OAuth2InvalidGrantError
    authorization = decision.authorization
    client_auth = await lock_and_reload_token_client(db_session, client_auth)
    if client_auth is None:
        raise OAuth2ProtocolError(error="invalid_client")
    client = client_auth.client
    if not client_allows_grant(client, OAuth2GrantType.device_code):
        raise OAuth2ProtocolError(error=ERR_UNAUTHORIZED_CLIENT)
    try:
        validate_requested_scope(
            requested_scope=authorization.scope,
            allowed_scopes=client.scopes,
        )
        validate_oidc_scope_enabled(
            requested_scope=authorization.scope,
            oidc_enabled=False,
        )
    except ValueError as exc:
        raise OAuth2ProtocolError(error=ERR_INVALID_SCOPE) from exc

    identity = await load_eligible_oauth2_user_identity(
        db_session=db_session,
        user_id=authorization.user_id,
        organization_id=authorization.organization_id,
    )
    if identity is None:
        raise OAuth2InvalidGrantError
    user, organization = identity.user, identity.organization
    try:
        await ensure_client_allows_user_organization(
            client=client,
            organization_id=organization.id,
            db_session=db_session,
        )
    except OAuth2ClientNotAllowedForUserOrganizationError as exc:
        raise OAuth2InvalidGrantError from exc

    marked_id = await db_session.scalar(
        update(OAuth2DeviceAuthorizationDB)
        .where(OAuth2DeviceAuthorizationDB.device_code_hash == device_code_hash)
        .where(OAuth2DeviceAuthorizationDB.used_at.is_(None))
        .where(OAuth2DeviceAuthorizationDB.approved_at.is_not(None))
        .where(OAuth2DeviceAuthorizationDB.denied_at.is_(None))
        .where(OAuth2DeviceAuthorizationDB.expires_at > now)
        .values(used_at=now)
        .returning(OAuth2DeviceAuthorizationDB.id)
        .execution_options(synchronize_session=False)
    )
    await db_session.flush()
    if marked_id is None:
        raise OAuth2InvalidGrantError
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
                scope=authorization.scope,
            ),
            grant_type=OAuth2GrantType.device_code,
            client_id=client_id,
            scope=authorization.scope,
            user_id=user.id,
            organization_id=organization.id,
            include_refresh_token=should_issue_refresh_token(
                settings=settings, client=client
            ),
        )
    )
    logger.info(
        (
            "event=oauth2_token_issued outcome=attempted client_id=%s subject_id=%s "
            "organization_id=%s session_id=%s grant_type=device_code"
        ),
        client_id,
        format_user_id(user.public_id),
        format_organization_id(organization.public_id),
        format_oauth2_session_id(issued.session_public_id),
    )
    return token_issuance.build_response(issued.token_pair)

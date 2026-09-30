"""Device-code polling and token issuance workflow."""

from dataclasses import dataclass
from datetime import datetime, UTC
from enum import StrEnum
from logging import getLogger
from typing import TYPE_CHECKING
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.dependencies import independent_transaction
from app.db.models.oauth2_device_authorization import OAuth2DeviceAuthorizationDB
from app.identity.dtos import IdentityDTO
from app.oauth2.clients.auth import ClientAuth, lock_and_reload_token_client
from app.oauth2.clients.dtos import OAuth2ClientReadDTO
from app.oauth2.clients.user_organization_authorization import (
    ensure_client_allows_user_organization,
    OAuth2ClientNotAllowedForUserOrganizationError,
)
from app.oauth2.devices.dtos import DeviceAuthorizationReadDTO
from app.oauth2.devices.mapping import to_device_authorization_dto
from app.oauth2.error_codes import OAuth2ErrorCode
from app.oauth2.errors import (
    OAuth2AuthorizationPendingError,
    OAuth2InvalidGrantError,
    OAuth2ProtocolError,
    OAuth2SlowDownError,
)
from app.oauth2.grants.request import DeviceCodeGrantRequest
from app.oauth2.grants.types import OAuth2GrantType, OAuth2SessionGrantType
from app.oauth2.schemas import OAuth2TokenResponse
from app.oauth2.settings import OAuth2Settings
from app.oauth2.tokens.access import (
    create_access_token_payload,
)
from app.oauth2.tokens.dtos import NewTokenSessionDTO
from app.oauth2.tokens.hash import hash_oauth2_token
from app.oauth2.tokens.issuance import TokenIssuanceService
from app.oauth2.user_identity import load_eligible_oauth2_user_identity
from app.oauth2.validation import (
    client_allows_grant,
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
    client_id: UUID,
) -> DevicePollDecision:
    """Evaluate polling and persist pending/slow-down state independently."""
    async with independent_transaction(session_factory) as db_session:
        # SQLite has no row-level SELECT FOR UPDATE. This no-op update acquires
        # the single-writer lock before the state-machine read, so concurrent
        # polls observe the preceding poll's committed timestamp and interval.
        authorization_id = await db_session.scalar(
            text(
                "UPDATE oauth2_device_authorization SET id = id "
                "WHERE device_code_hash = :device_code_hash RETURNING id"
            ),
            {"device_code_hash": device_code_hash},
        )
        if authorization_id is None:
            return DevicePollDecision(DevicePollStatus.INVALID)
        now = datetime.now(UTC)
        authorization_row = await db_session.scalar(
            select(OAuth2DeviceAuthorizationDB).where(
                OAuth2DeviceAuthorizationDB.id == authorization_id
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


def _validate_initial_device_client(
    *, settings: OAuth2Settings, client_auth: ClientAuth | None
) -> ClientAuth:
    """Validate the client before reading or mutating device polling state."""
    if not settings.is_grant_enabled(OAuth2GrantType.DEVICE_CODE):
        raise OAuth2ProtocolError(error=OAuth2ErrorCode.UNSUPPORTED_GRANT_TYPE)
    if client_auth is None:
        raise OAuth2ProtocolError(error=OAuth2ErrorCode.INVALID_CLIENT)
    client = client_auth.client
    if not client.is_active:
        raise OAuth2ProtocolError(error=OAuth2ErrorCode.INVALID_CLIENT)
    return client_auth


async def _reload_and_validate_device_client(
    *,
    db_session: AsyncSession,
    client_auth: ClientAuth,
    authorization: DeviceAuthorizationReadDTO,
) -> OAuth2ClientReadDTO:
    """Reload the client and validate its current device-code policy."""
    # Release the client-authentication read before taking SQLite's writer lock
    # for device authorization consumption and token issuance.
    await db_session.commit()
    current_auth = await lock_and_reload_token_client(db_session, client_auth)
    if current_auth is None:
        raise OAuth2ProtocolError(error=OAuth2ErrorCode.INVALID_CLIENT)
    client = current_auth.client
    if not client_allows_grant(client, OAuth2GrantType.DEVICE_CODE):
        raise OAuth2ProtocolError(error=OAuth2ErrorCode.UNAUTHORIZED_CLIENT)
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
        raise OAuth2ProtocolError(error=OAuth2ErrorCode.INVALID_SCOPE) from exc
    return client


async def _load_device_identity(
    *,
    db_session: AsyncSession,
    client: OAuth2ClientReadDTO,
    authorization: DeviceAuthorizationReadDTO,
) -> IdentityDTO:
    """Load the eligible identity and enforce current organization access."""
    identity = await load_eligible_oauth2_user_identity(
        db_session=db_session,
        user_id=authorization.user_id,
        organization_id=authorization.organization_id,
    )
    if identity is None:
        raise OAuth2InvalidGrantError
    try:
        await ensure_client_allows_user_organization(
            client=client,
            organization_id=identity.organization.id,
            db_session=db_session,
        )
    except OAuth2ClientNotAllowedForUserOrganizationError as exc:
        raise OAuth2InvalidGrantError from exc
    return identity


async def _consume_device_authorization(
    *,
    db_session: AsyncSession,
    device_code_hash: str,
    now: datetime,
) -> None:
    """Atomically consume an approved, unexpired device authorization."""
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


async def _issue_device_tokens(  # noqa: PLR0913
    *,
    db_session: AsyncSession,
    settings: OAuth2Settings,
    signing_key: ed25519.Ed25519PrivateKey | str,
    client: OAuth2ClientReadDTO,
    authorization: DeviceAuthorizationReadDTO,
    identity: IdentityDTO,
) -> OAuth2TokenResponse:
    """Persist a device-code token session and build its response."""
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
                scope=authorization.scope,
            ),
            grant_type=OAuth2SessionGrantType.DEVICE_CODE,
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
        str(user.public_id),
        str(organization.public_id),
        str(issued.session_public_id),
    )
    return token_issuance.build_response(issued.tokens)


# The polling state machine stays ordered here so each terminal and retry state
# is visible before the authorization is consumed.
async def handle_device_code_grant(  # noqa: PLR0913
    request: DeviceCodeGrantRequest,
    *,
    db_session: AsyncSession,
    session_factory: "async_sessionmaker[AsyncSession]",
    settings: OAuth2Settings,
    client_auth: ClientAuth | None,
    signing_key: ed25519.Ed25519PrivateKey | str,
) -> OAuth2TokenResponse:
    """Exchange an approved OAuth2 device code for an OAuth2 token response."""
    validated_client_auth = _validate_initial_device_client(
        settings=settings,
        client_auth=client_auth,
    )
    client = validated_client_auth.client
    client_id = client.client_id
    device_code_hash = hash_oauth2_token(
        token=request.device_code,
        secret=settings.token_hash_secret.get_secret_value(),
    )
    decision = await evaluate_device_poll(
        session_factory=session_factory,
        device_code_hash=device_code_hash,
        client_id=client_id,
    )
    if decision.status == DevicePollStatus.PENDING:
        raise OAuth2AuthorizationPendingError
    if decision.status == DevicePollStatus.SLOW_DOWN:
        raise OAuth2SlowDownError
    if decision.status == DevicePollStatus.DENIED:
        raise OAuth2ProtocolError(error=OAuth2ErrorCode.ACCESS_DENIED)
    if decision.status == DevicePollStatus.EXPIRED:
        raise OAuth2ProtocolError(error=OAuth2ErrorCode.EXPIRED_TOKEN)
    if decision.status == DevicePollStatus.INVALID or decision.authorization is None:
        raise OAuth2InvalidGrantError
    authorization = decision.authorization
    now = datetime.now(UTC)
    client = await _reload_and_validate_device_client(
        db_session=db_session,
        client_auth=validated_client_auth,
        authorization=authorization,
    )
    identity = await _load_device_identity(
        db_session=db_session,
        client=client,
        authorization=authorization,
    )
    await _consume_device_authorization(
        db_session=db_session,
        device_code_hash=device_code_hash,
        now=now,
    )
    return await _issue_device_tokens(
        db_session=db_session,
        settings=settings,
        signing_key=signing_key,
        client=client,
        authorization=authorization,
        identity=identity,
    )

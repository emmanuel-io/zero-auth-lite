"""Refresh-token rotation workflow and its atomic persistence helpers."""

from datetime import datetime, UTC
from logging import getLogger
from typing import cast, TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.dependencies import independent_transaction
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_state import (
    OAuth2RefreshTokenHistoryDB,
    OAuth2TokenStateDB,
)
from app.identity.dtos import IdentityDTO
from app.oauth2.clients.auth import ClientAuth, lock_and_reload_token_client
from app.oauth2.clients.dtos import OAuth2ClientReadDTO
from app.oauth2.clients.user_organization_authorization import (
    ensure_client_allows_user_organization,
    OAuth2ClientNotAllowedForUserOrganizationError,
)
from app.oauth2.error_codes import OAuth2ErrorCode
from app.oauth2.errors import OAuth2InvalidGrantError, OAuth2ProtocolError
from app.oauth2.grants.request import RefreshTokenGrantRequest
from app.oauth2.grants.types import OAuth2GrantType
from app.oauth2.schemas import OAuth2TokenResponse
from app.oauth2.sessions.mapping import to_oauth2_token_family_dto
from app.oauth2.settings import OAuth2Settings
from app.oauth2.tokens.access import (
    create_access_token_payload,
)
from app.oauth2.tokens.dtos import (
    OAuth2TokenFamilyReadDTO,
    OAuth2TokenStateUpdateDTO,
)
from app.oauth2.tokens.hash import hash_oauth2_token
from app.oauth2.tokens.issuance import TokenIssuanceService
from app.oauth2.user_identity import load_eligible_oauth2_user_identity
from app.oauth2.validation import (
    client_allows_grant,
    validate_oidc_scope_enabled,
    validate_requested_scope,
)


logger = getLogger(__name__)
REFRESH_SCOPE_NARROWING_UNSUPPORTED = "scope narrowing is not supported"


if TYPE_CHECKING:
    from sqlalchemy.engine import CursorResult
    from sqlalchemy.ext.asyncio import async_sessionmaker


async def rotate_token_state(
    *,
    db_session: AsyncSession,
    settings: OAuth2Settings,
    session_id: int,
    current_refresh_hash: str,
    data: OAuth2TokenStateUpdateDTO,
) -> bool:
    """Atomically replace token state only if its refresh token is current."""
    result = cast(
        "CursorResult[object]",
        await db_session.execute(
            update(OAuth2TokenStateDB)
            .where(OAuth2TokenStateDB.session_id == session_id)
            .where(OAuth2TokenStateDB.refresh_token_hash == current_refresh_hash)
            .values(
                access_expires_at=data.access_expires_at,
                access_jti=data.access_jti,
                access_token_hash=hash_oauth2_token(
                    token=data.access_token,
                    secret=settings.token_hash_secret.get_secret_value(),
                ),
                refresh_expires_at=data.refresh_expires_at,
                refresh_token_hash=hash_oauth2_token(
                    token=data.refresh_token,
                    secret=settings.token_hash_secret.get_secret_value(),
                ),
            )
        ),
    )
    return result.rowcount > 0


async def revoke_reused_refresh_family(
    *,
    session_factory: "async_sessionmaker[AsyncSession]",
    refresh_hash: str,
) -> None:
    """Revoke a family in its own transaction when an old token is reused."""
    async with independent_transaction(session_factory) as db_session:
        session_row = (
            await db_session.execute(
                select(OAuth2TokenStateDB.session_id, OAuth2SessionDB.public_id)
                .join(
                    OAuth2RefreshTokenHistoryDB,
                    OAuth2RefreshTokenHistoryDB.session_id
                    == OAuth2TokenStateDB.session_id,
                )
                .join(
                    OAuth2SessionDB,
                    OAuth2SessionDB.id == OAuth2TokenStateDB.session_id,
                )
                .where(OAuth2RefreshTokenHistoryDB.token_hash == refresh_hash)
            )
        ).one_or_none()
        if session_row is None:
            return
        session_id, session_public_id = session_row
        await db_session.execute(
            update(OAuth2SessionDB)
            .where(OAuth2SessionDB.id == session_id)
            .where(OAuth2SessionDB.ended_at.is_(None))
            .values(ended_at=datetime.now(UTC))
        )
        await db_session.execute(
            delete(OAuth2TokenStateDB).where(
                OAuth2TokenStateDB.session_id == session_id
            )
        )
    logger.warning(
        (
            "event=oauth2_refresh_reuse outcome=revoked session_id=%s "
            "reason=reused_refresh_token"
        ),
        str(session_public_id),
    )


async def expire_refresh_family(
    *,
    session_factory: "async_sessionmaker[AsyncSession]",
    session_id: int,
    refresh_hash: str,
    expired_at: datetime,
) -> None:
    """Remove an expired current pair in an independent transaction."""
    async with independent_transaction(session_factory) as db_session:
        deleted_session_id = await db_session.scalar(
            delete(OAuth2TokenStateDB)
            .where(OAuth2TokenStateDB.session_id == session_id)
            .where(OAuth2TokenStateDB.refresh_token_hash == refresh_hash)
            .where(OAuth2TokenStateDB.refresh_expires_at <= expired_at)
            .returning(OAuth2TokenStateDB.session_id)
        )
        if deleted_session_id is None:
            return
        await db_session.execute(
            update(OAuth2SessionDB)
            .where(OAuth2SessionDB.id == deleted_session_id)
            .where(OAuth2SessionDB.ended_at.is_(None))
            .values(ended_at=expired_at)
        )


async def _load_refresh_family(
    *,
    db_session: AsyncSession,
    session_factory: "async_sessionmaker[AsyncSession]",
    refresh_hash: str,
) -> OAuth2TokenFamilyReadDTO:
    """Load a current family or revoke a family found through reuse history."""
    family_row = (
        await db_session.execute(
            select(OAuth2SessionDB, OAuth2TokenStateDB)
            .join(
                OAuth2TokenStateDB, OAuth2TokenStateDB.session_id == OAuth2SessionDB.id
            )
            .where(OAuth2TokenStateDB.refresh_token_hash == refresh_hash)
        )
    ).one_or_none()
    if family_row is None:
        await revoke_reused_refresh_family(
            session_factory=session_factory,
            refresh_hash=refresh_hash,
        )
        raise OAuth2InvalidGrantError
    return to_oauth2_token_family_dto(*family_row)


async def _require_unexpired_refresh_family(
    *,
    family: OAuth2TokenFamilyReadDTO,
    session_factory: "async_sessionmaker[AsyncSession]",
    refresh_hash: str,
) -> datetime:
    """Reject an unusable refresh deadline and persist expiry cleanup."""
    refresh_expires_at = family.token_state.refresh_expires_at
    if refresh_expires_at is None:
        raise OAuth2InvalidGrantError
    now = datetime.now(UTC)
    if refresh_expires_at <= now:
        await expire_refresh_family(
            session_factory=session_factory,
            session_id=family.token_state.session_id,
            refresh_hash=refresh_hash,
            expired_at=now,
        )
        raise OAuth2InvalidGrantError
    return refresh_expires_at


async def _validate_refresh_client(
    *,
    db_session: AsyncSession,
    settings: OAuth2Settings,
    client_auth: ClientAuth | None,
    family: OAuth2TokenFamilyReadDTO,
) -> OAuth2ClientReadDTO:
    """Reload the bound client and revalidate its current refresh policy."""
    if client_auth is not None:
        # Release the family and client-authentication reads before taking
        # SQLite's writer lock for refresh rotation.
        await db_session.commit()
    current_auth = await lock_and_reload_token_client(db_session, client_auth)
    oauth2_session = family.session
    if current_auth is None or current_auth.client_id != oauth2_session.client_id:
        raise OAuth2InvalidGrantError
    client = current_auth.client
    if not client.is_active or not client_allows_grant(
        client, OAuth2GrantType.REFRESH_TOKEN
    ):
        raise OAuth2InvalidGrantError
    try:
        validate_requested_scope(
            requested_scope=oauth2_session.scope,
            allowed_scopes=client.scopes,
        )
        validate_oidc_scope_enabled(
            requested_scope=oauth2_session.scope,
            oidc_enabled=settings.oidc_enabled,
        )
    except ValueError as exc:
        raise OAuth2InvalidGrantError from exc
    if not oauth2_session.is_active():
        raise OAuth2InvalidGrantError
    return client


async def _load_refresh_identity(
    *,
    db_session: AsyncSession,
    client: OAuth2ClientReadDTO,
    family: OAuth2TokenFamilyReadDTO,
) -> IdentityDTO:
    """Load the eligible user identity and enforce current organization access."""
    oauth2_session = family.session
    identity = (
        await load_eligible_oauth2_user_identity(
            db_session=db_session,
            user_id=oauth2_session.user_id,
            organization_id=oauth2_session.organization_id,
        )
        if oauth2_session.user_id is not None
        else None
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


async def _rotate_refresh_family(  # noqa: PLR0913
    *,
    db_session: AsyncSession,
    settings: OAuth2Settings,
    signing_key: ed25519.Ed25519PrivateKey | str,
    refresh_hash: str,
    refresh_deadline: datetime,
    family: OAuth2TokenFamilyReadDTO,
    identity: IdentityDTO,
) -> OAuth2TokenResponse:
    """Create and atomically persist replacement tokens and reuse history."""
    oauth2_session = family.session
    token_state = family.token_state
    user, organization = identity.user, identity.organization
    token_issuance = TokenIssuanceService(
        db_session=db_session,
        settings=settings,
        signing_key=signing_key,
    )
    tokens = token_issuance.create_rotation_tokens(
        access_payload=create_access_token_payload(
            user_public_id=user.public_id,
            organization_public_id=organization.public_id,
            audience=settings.access_token_audience,
            client_id=oauth2_session.client_id,
            scope=oauth2_session.scope,
        ),
        refresh_deadline=refresh_deadline,
    )
    if tokens.refresh_token is None or tokens.refresh_expires_at is None:
        raise OAuth2InvalidGrantError
    rotated = await rotate_token_state(
        db_session=db_session,
        settings=settings,
        session_id=token_state.session_id,
        current_refresh_hash=refresh_hash,
        data=OAuth2TokenStateUpdateDTO(
            access_expires_at=tokens.access_expires_at,
            access_jti=tokens.access_jti,
            access_token=tokens.access_token,
            refresh_expires_at=tokens.refresh_expires_at,
            refresh_token=tokens.refresh_token,
        ),
    )
    if not rotated:
        logger.info(
            "event=oauth2_refresh_rotation outcome=conflict "
            "session_id=%s client_id=%s grant_type=%s",
            str(oauth2_session.public_id),
            oauth2_session.client_id,
            oauth2_session.grant_type,
        )
        raise OAuth2InvalidGrantError
    db_session.add(
        OAuth2RefreshTokenHistoryDB(
            token_hash=refresh_hash,
            session_id=token_state.session_id,
        )
    )
    await db_session.flush()
    logger.info(
        (
            "event=oauth2_refresh_rotation outcome=attempted session_id=%s "
            "client_id=%s grant_type=%s"
        ),
        str(oauth2_session.public_id),
        oauth2_session.client_id,
        oauth2_session.grant_type,
    )
    return token_issuance.build_response(tokens)


# Current-token rotation, consumed-token history, and replacement issuance share
# the request transaction. Reuse revocation and expiry cleanup use independent
# transactions so those security outcomes survive the returned invalid_grant.
async def handle_refresh_token_grant(  # noqa: PLR0913
    request: RefreshTokenGrantRequest,
    *,
    db_session: AsyncSession,
    session_factory: "async_sessionmaker[AsyncSession]",
    settings: OAuth2Settings,
    client_auth: ClientAuth | None,
    signing_key: ed25519.Ed25519PrivateKey | str,
) -> OAuth2TokenResponse:
    """Validate and atomically rotate one refresh token."""
    if not settings.is_grant_enabled(OAuth2GrantType.REFRESH_TOKEN):
        raise OAuth2ProtocolError(error=OAuth2ErrorCode.UNSUPPORTED_GRANT_TYPE)
    refresh_hash = hash_oauth2_token(
        token=request.refresh_token,
        secret=settings.token_hash_secret.get_secret_value(),
    )
    family = await _load_refresh_family(
        db_session=db_session,
        session_factory=session_factory,
        refresh_hash=refresh_hash,
    )
    if request.scope is not None:
        raise OAuth2InvalidGrantError(REFRESH_SCOPE_NARROWING_UNSUPPORTED)
    refresh_deadline = await _require_unexpired_refresh_family(
        family=family,
        session_factory=session_factory,
        refresh_hash=refresh_hash,
    )
    client = await _validate_refresh_client(
        db_session=db_session,
        settings=settings,
        client_auth=client_auth,
        family=family,
    )
    identity = await _load_refresh_identity(
        db_session=db_session,
        client=client,
        family=family,
    )
    return await _rotate_refresh_family(
        db_session=db_session,
        settings=settings,
        signing_key=signing_key,
        refresh_hash=refresh_hash,
        refresh_deadline=refresh_deadline,
        family=family,
        identity=identity,
    )

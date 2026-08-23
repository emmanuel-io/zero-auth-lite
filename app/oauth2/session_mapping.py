"""ORM-to-DTO mapping for OAuth2 authorization sessions."""

from typing import TYPE_CHECKING

from app.core.time import as_utc_aware
from app.db.models.oauth2_session import OAuth2SessionDB
from app.oauth2.session_dtos import OAuth2SessionReadDTO
from app.oauth2.tokens.dtos import OAuth2TokenFamilyReadDTO, TokenPairReadDTO
from app.public_ids import PublicId


if TYPE_CHECKING:
    from app.db.models.oauth2_token_pair import OAuth2TokenPairDB


def to_oauth2_session_dto(session: OAuth2SessionDB) -> OAuth2SessionReadDTO:
    """Convert an OAuth2 session row to its stable DTO."""
    return OAuth2SessionReadDTO(
        id=session.id,
        public_id=PublicId(session.public_id),
        client_id=session.client_id,
        grant_type=session.grant_type,
        scope=session.scope,
        user_id=session.user_id,
        organization_id=session.organization_id,
        ended_at=(
            as_utc_aware(session.ended_at) if session.ended_at is not None else None
        ),
        created_at=as_utc_aware(session.created_at),
        updated_at=as_utc_aware(session.updated_at),
    )


def to_oauth2_token_family_dto(
    session: OAuth2SessionDB, token_pair: "OAuth2TokenPairDB"
) -> OAuth2TokenFamilyReadDTO:
    """Convert joined session and token rows to one explicit family DTO."""
    return OAuth2TokenFamilyReadDTO(
        session=to_oauth2_session_dto(session),
        token_pair=TokenPairReadDTO.model_validate(token_pair),
    )

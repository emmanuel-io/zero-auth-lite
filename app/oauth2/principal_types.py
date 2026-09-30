"""OAuth2 bearer principal type claims."""

from enum import StrEnum

from app.oauth2.grants.types import OAuth2SessionGrantType


class PrincipalType(StrEnum):
    """Explicit OAuth2 bearer principal type."""

    USER = "user"
    CLIENT = "client"


USER_SESSION_GRANTS = frozenset(
    {OAuth2SessionGrantType.AUTHORIZATION_CODE, OAuth2SessionGrantType.DEVICE_CODE}
)


def session_principal_type(
    *,
    grant_type: OAuth2SessionGrantType | str,
    user_id: int | None,
    organization_id: int | None,
) -> PrincipalType:
    """Return the principal kind for one valid persisted OAuth2 session."""
    try:
        normalized_grant = OAuth2SessionGrantType(grant_type)
    except ValueError as exc:
        msg = f"Unsupported persisted OAuth2 grant type: {grant_type}."
        raise ValueError(msg) from exc

    if normalized_grant is OAuth2SessionGrantType.CLIENT_CREDENTIALS:
        if user_id is None and organization_id is None:
            return PrincipalType.CLIENT
    elif (
        normalized_grant in USER_SESSION_GRANTS
        and user_id is not None
        and organization_id is not None
    ):
        return PrincipalType.USER

    msg = f"OAuth2 grant {normalized_grant.value} has an invalid principal binding."
    raise ValueError(msg)

"""FastAPI dependencies for OIDC services."""

from typing import Annotated

from fastapi import Depends

from app.db.dependencies import DbSessionDep
from app.oauth2.oidc.userinfo import OIDCUserInfoService
from app.settings.dependencies import OAuth2SettingsDep


def get_oidc_userinfo_service(
    db_session: DbSessionDep,
    settings: OAuth2SettingsDep,
) -> OIDCUserInfoService:
    """Provide the focused OIDC UserInfo service."""
    return OIDCUserInfoService(
        db_session=db_session,
        settings=settings,
    )


OIDCUserInfoServiceDep = Annotated[
    OIDCUserInfoService,
    Depends(get_oidc_userinfo_service),
]

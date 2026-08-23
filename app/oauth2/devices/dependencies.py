"""FastAPI dependencies for device OAuth2 services."""

from typing import Annotated

from fastapi import Depends

from app.db.dependencies import DbSessionDep
from app.oauth2.devices.authorization import DeviceAuthorizationService
from app.settings.dependencies import OAuth2SettingsDep


def get_device_authorization_service(
    settings: OAuth2SettingsDep,
    db_session: DbSessionDep,
) -> DeviceAuthorizationService:
    """Provide the device authorization service."""
    return DeviceAuthorizationService(
        settings=settings,
        db_session=db_session,
    )


DeviceAuthorizationServiceDep = Annotated[
    DeviceAuthorizationService,
    Depends(get_device_authorization_service),
]

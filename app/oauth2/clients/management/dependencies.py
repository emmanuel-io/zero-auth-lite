"""FastAPI dependencies for OAuth2 client administration services."""

from typing import Annotated

from fastapi import Depends

from app.db.dependencies import DbSessionDep, DbSessionFactoryDep
from app.oauth2.clients.management.credential_rotation import (
    OAuth2ClientCredentialRotationService,
)
from app.oauth2.clients.management.machine_organization_access import (
    OAuth2ClientMachineOrganizationAccessService,
)
from app.oauth2.clients.management.policy import OAuth2ClientPolicy
from app.oauth2.clients.management.registration import (
    OAuth2ClientRegistrationService,
)
from app.oauth2.clients.management.registry import OAuth2ClientRegistryService
from app.oauth2.clients.management.user_organization_access import (
    OAuth2ClientUserOrganizationAccessService,
)
from app.password.dependencies import PasswordHasherDep
from app.settings.dependencies import OAuth2SettingsDep


def _policy(settings: OAuth2SettingsDep) -> OAuth2ClientPolicy:
    """Build the request-scoped OAuth2 client policy."""
    return OAuth2ClientPolicy(settings)


def get_oauth2_client_registration_service(
    db_session: DbSessionDep,
    settings: OAuth2SettingsDep,
    password_hasher: PasswordHasherDep,
) -> OAuth2ClientRegistrationService:
    """Build the client registration service."""
    return OAuth2ClientRegistrationService(
        db_session=db_session,
        policy=_policy(settings),
        password_hasher=password_hasher,
    )


def get_oauth2_client_registry_service(
    db_session: DbSessionDep,
    settings: OAuth2SettingsDep,
) -> OAuth2ClientRegistryService:
    """Build the client registry administration service."""
    return OAuth2ClientRegistryService(
        db_session=db_session,
        policy=_policy(settings),
    )


def get_oauth2_client_user_organization_access_service(
    db_session: DbSessionDep,
) -> OAuth2ClientUserOrganizationAccessService:
    """Build the user-organization policy service."""
    return OAuth2ClientUserOrganizationAccessService(
        db_session=db_session,
    )


def get_oauth2_client_machine_organization_access_service(
    db_session: DbSessionDep,
) -> OAuth2ClientMachineOrganizationAccessService:
    """Build the machine-organization policy service."""
    return OAuth2ClientMachineOrganizationAccessService(
        db_session=db_session,
    )


def get_oauth2_client_credential_rotation_service(
    session_factory: DbSessionFactoryDep,
    password_hasher: PasswordHasherDep,
) -> OAuth2ClientCredentialRotationService:
    """Build the client credential service."""
    return OAuth2ClientCredentialRotationService(
        session_factory=session_factory,
        password_hasher=password_hasher,
    )


OAuth2ClientRegistrationServiceDep = Annotated[
    OAuth2ClientRegistrationService,
    Depends(get_oauth2_client_registration_service),
]
OAuth2ClientRegistryServiceDep = Annotated[
    OAuth2ClientRegistryService,
    Depends(get_oauth2_client_registry_service),
]
OAuth2ClientUserOrganizationAccessServiceDep = Annotated[
    OAuth2ClientUserOrganizationAccessService,
    Depends(get_oauth2_client_user_organization_access_service),
]
OAuth2ClientMachineOrganizationAccessServiceDep = Annotated[
    OAuth2ClientMachineOrganizationAccessService,
    Depends(get_oauth2_client_machine_organization_access_service),
]
OAuth2ClientCredentialRotationServiceDep = Annotated[
    OAuth2ClientCredentialRotationService,
    Depends(get_oauth2_client_credential_rotation_service),
]

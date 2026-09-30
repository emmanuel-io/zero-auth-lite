"""Map OAuth2 client HTTP payloads and service DTOs."""

from app.api.v1.server.oauth2_clients.schemas import (
    OAuth2ClientCreateRequest,
    OAuth2ClientCreateResponse,
    OAuth2ClientMachineOrganizationAccessResponse,
    OAuth2ClientReadResponse,
    OAuth2ClientReplaceRequest,
    OAuth2ClientSecretResponse,
    OAuth2ClientUserOrganizationsResponse,
)
from app.oauth2.clients.dtos import (
    OAuth2ClientCreateResultDTO,
    OAuth2ClientMachineOrganizationsDTO,
    OAuth2ClientReadDTO,
    OAuth2ClientRegistrationDTO,
    OAuth2ClientRegistryReplaceDTO,
    OAuth2ClientSecretDTO,
    OAuth2ClientUserOrganizationsDTO,
)


def client_registration_dto(
    payload: OAuth2ClientCreateRequest,
) -> OAuth2ClientRegistrationDTO:
    """Convert an HTTP creation payload to a service DTO."""
    return OAuth2ClientRegistrationDTO(
        **payload.model_dump(exclude={"grant_types", "redirect_uris"}),
        grant_types=[grant.value for grant in payload.grant_types],
        redirect_uris=[str(uri) for uri in payload.redirect_uris],
    )


def client_replace_dto(
    payload: OAuth2ClientReplaceRequest,
) -> OAuth2ClientRegistryReplaceDTO:
    """Convert an HTTP replacement payload to a service DTO."""
    return OAuth2ClientRegistryReplaceDTO(
        **payload.model_dump(exclude={"grant_types", "redirect_uris"}),
        grant_types=[grant.value for grant in payload.grant_types],
        redirect_uris=[str(uri) for uri in payload.redirect_uris],
    )


def client_response(dto: OAuth2ClientReadDTO) -> OAuth2ClientReadResponse:
    """Convert a client service DTO to its public response."""
    return OAuth2ClientReadResponse(
        **dto.model_dump(exclude={"client_secret", "redirect_uris"}),
        redirect_uris=dto.redirect_uris or [],
    )


def client_create_response(
    dto: OAuth2ClientCreateResultDTO,
) -> OAuth2ClientCreateResponse:
    """Convert a registration result to its one-time HTTP response."""
    return OAuth2ClientCreateResponse(
        **client_response(dto.client).model_dump(),
        client_secret=dto.client_secret,
    )


def user_organizations_response(
    dto: OAuth2ClientUserOrganizationsDTO,
) -> OAuth2ClientUserOrganizationsResponse:
    """Convert a user-organization policy DTO to its HTTP response."""
    return OAuth2ClientUserOrganizationsResponse.model_validate(
        dto,
        from_attributes=True,
    )


def machine_organizations_response(
    dto: OAuth2ClientMachineOrganizationsDTO,
) -> OAuth2ClientMachineOrganizationAccessResponse:
    """Convert a machine-organization policy DTO to its HTTP response."""
    return OAuth2ClientMachineOrganizationAccessResponse.model_validate(
        dto, from_attributes=True
    )


def client_secret_response(dto: OAuth2ClientSecretDTO) -> OAuth2ClientSecretResponse:
    """Convert a rotated secret DTO to its one-time HTTP response."""
    return OAuth2ClientSecretResponse(
        client_id=dto.client_id,
        client_secret=dto.client_secret,
    )

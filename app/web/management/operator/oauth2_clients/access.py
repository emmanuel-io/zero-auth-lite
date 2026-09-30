"""OAuth2 client organization-access management actions."""

from typing import Annotated

from fastapi import APIRouter, Form, Request, Response

from app.oauth2.clients.dtos import (
    OAuth2ClientMachineOrganizationUpdateDTO,
    OAuth2ClientUserOrganizationUpdateDTO,
)
from app.oauth2.clients.management.dependencies import (
    OAuth2ClientMachineOrganizationAccessServiceDep,
    OAuth2ClientUserOrganizationAccessServiceDep,
)
from app.oauth2.clients.management.errors import OAuth2ClientServiceError
from app.web.management.dependencies import OperatorFormDep
from app.web.management.errors import raise_management_oauth2_client_error
from app.web.management.forms import split_non_empty_lines
from app.web.management.ids import OAuth2ClientIdPath
from app.web.management.notices import ManagementNotice
from app.web.management.operator.forms import (
    MachineOrganizationForm,
    UserOrganizationForm,
)
from app.web.management.responses import mutation_success
from app.web.routes import ManagementPageRoute
from app.web.validation import validated_model


router = APIRouter(route_class=ManagementPageRoute)


@router.post("/oauth2/clients/{client_id}/user-organizations")
async def update_user_organizations(
    client_id: OAuth2ClientIdPath,
    request: Request,
    service: OAuth2ClientUserOrganizationAccessServiceDep,
    user_ctx: OperatorFormDep,
    form: Annotated[UserOrganizationForm, Form()],
) -> Response:
    """Update the client organizations available to user grants."""
    dto = validated_model(
        OAuth2ClientUserOrganizationUpdateDTO,
        user_organization_access=form.user_organization_access,
        organization_ids=split_non_empty_lines(form.organization_ids),
    )
    try:
        await service.replace_user_organizations(
            client_id=client_id,
            dto=dto,
            operator_ctx=user_ctx,
        )
    except OAuth2ClientServiceError as exc:
        raise_management_oauth2_client_error(exc)
    return mutation_success(
        request,
        f"/management/operator/oauth2/clients/{client_id}",
        notice=ManagementNotice.USER_ACCESS_UPDATED,
    )


@router.post("/oauth2/clients/{client_id}/machine-organizations")
async def update_machine_organizations(
    client_id: OAuth2ClientIdPath,
    request: Request,
    service: OAuth2ClientMachineOrganizationAccessServiceDep,
    user_ctx: OperatorFormDep,
    form: Annotated[MachineOrganizationForm, Form()],
) -> Response:
    """Update the client organizations available to machine grants."""
    dto = validated_model(
        OAuth2ClientMachineOrganizationUpdateDTO,
        machine_organization_access=form.machine_organization_access,
        organization_ids=split_non_empty_lines(form.organization_ids),
    )
    try:
        await service.replace_machine_organization_access(
            client_id=client_id,
            dto=dto,
            operator_ctx=user_ctx,
        )
    except OAuth2ClientServiceError as exc:
        raise_management_oauth2_client_error(exc)
    return mutation_success(
        request,
        f"/management/operator/oauth2/clients/{client_id}",
        notice=ManagementNotice.MACHINE_ACCESS_UPDATED,
    )

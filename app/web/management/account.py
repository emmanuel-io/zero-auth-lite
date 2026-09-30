"""Current-user self-service browser routes."""

from typing import Annotated

from fastapi import APIRouter, Form, Query, Request, Response

from app.browser_sessions.dependencies import (
    CurrentBrowserUserContextDep,
)
from app.browser_sessions.service_dependencies import BrowserSessionLifecycleServiceDep
from app.identity.dependencies import (
    BrowserFormUserSelfServiceDep,
    BrowserUserSelfServiceDep,
)
from app.identity.users.dtos import UserSelfPatchDTO
from app.identity.users.types import UserEmail, UserFirstName, UserLastName
from app.openapi_tags import ACCOUNT_UI_TAG
from app.web.management.forms import ManagementForm
from app.web.management.notices import ManagementNotice
from app.web.management.responses import mutation_success, render_management_page
from app.web.routes import ManagementPageRoute
from app.web.validation import validated_model


class AccountProfileForm(ManagementForm):
    """Validated account-profile form fields."""

    email: UserEmail
    first_name: UserFirstName
    last_name: UserLastName


router = APIRouter(tags=[ACCOUNT_UI_TAG], route_class=ManagementPageRoute)


@router.get("")
async def account_page(
    request: Request,
    user_service: BrowserUserSelfServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: CurrentBrowserUserContextDep,
    notice: Annotated[str | None, Query()] = None,
) -> Response:
    """Show the current user's editable profile."""
    profile = await user_service.read()
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/account.html",
        profile=profile,
        notice=notice,
    )


@router.post("")
async def update_account(
    request: Request,
    user_service: BrowserFormUserSelfServiceDep,
    form: Annotated[AccountProfileForm, Form()],
) -> Response:
    """Update fields owned by the current user."""
    dto = validated_model(
        UserSelfPatchDTO,
        email=form.email,
        first_name=form.first_name,
        last_name=form.last_name,
    )
    await user_service.patch(data=dto)
    return mutation_success(
        request, "/management/account", notice=ManagementNotice.PROFILE_UPDATED
    )

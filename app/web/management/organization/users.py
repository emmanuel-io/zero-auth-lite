"""Current-organization user browser routes."""

from typing import Annotated

from fastapi import APIRouter, Form, Query, Request, Response

from app.browser_sessions.service_dependencies import BrowserSessionLifecycleServiceDep
from app.identity.users.criteria import OrganizationUserSearchCriteriaDTO
from app.identity.users.dtos import (
    OrganizationUserCreateDTO,
    OrganizationUserReplaceDTO,
)
from app.web.management.dependencies import (
    OrganizationAdminFormDep,
    OrganizationAdminUIDep,
    OrganizationFormUsersServiceDep,
    OrganizationUIUsersServiceDep,
)
from app.web.management.forms import ConfirmedFormDep
from app.web.management.ids import UserIdPath
from app.web.management.notices import ManagementNotice
from app.web.management.organization.forms import (
    OrganizationUserCreateForm,
    OrganizationUserReplaceForm,
)
from app.web.management.organization.queries import OrganizationUserFilters
from app.web.management.organization.views import OrganizationUserView
from app.web.management.pagination import pagination_links
from app.web.management.queries import ManagementPagination
from app.web.management.responses import (
    mutation_success,
    render_management_page,
    render_user_delete_confirmation,
    UserDeleteConfirmation,
)
from app.web.routes import ManagementPageRoute
from app.web.validation import validated_model


router = APIRouter(route_class=ManagementPageRoute)


@router.get("/users")
async def users(  # noqa: PLR0913, PLR0917
    request: Request,
    users_service: OrganizationUIUsersServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OrganizationAdminUIDep,
    query: Annotated[OrganizationUserFilters, Query()],
    pagination: Annotated[ManagementPagination, Query()],
    notice: Annotated[str | None, Query()] = None,
) -> Response:
    """Render the user list."""
    page = await users_service.search(
        criteria=OrganizationUserSearchCriteriaDTO(
            q=query.q,
            role=query.role.value if query.role is not None else None,
            active=query.active,
            email_verified=query.email_verified,
            created_from=query.created_from,
            created_to=query.created_to,
            offset=pagination.offset,
            limit=pagination.limit,
        )
    )
    filters = {
        "q": query.q,
        "role": query.role,
        "active": query.active,
        "email_verified": query.email_verified,
        "created_from": query.created_from,
        "created_to": query.created_to,
    }
    links = pagination_links(
        "/management/organization/users",
        filters=filters,
        offset=pagination.offset,
        limit=pagination.limit,
        total=page.total,
    )
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/organization/users.html",
        users=[OrganizationUserView.from_dto(item) for item in page.items],
        total=page.total,
        offset=pagination.offset,
        limit=pagination.limit,
        filters=filters,
        previous_url=links.previous_url,
        next_url=links.next_url,
        notice=notice,
    )


@router.get("/users/new")
async def new_user(
    request: Request,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OrganizationAdminUIDep,
) -> Response:
    """Render the new-user invitation form."""
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/organization/user_form.html",
        user=None,
        action="/management/organization/users",
        heading="Add or invite a user",
        submit_label="Create user",
    )


@router.post("/users")
async def create_user(
    request: Request,
    users_service: OrganizationFormUsersServiceDep,
    _user_ctx: OrganizationAdminFormDep,
    form: Annotated[OrganizationUserCreateForm, Form()],
) -> Response:
    """Invite a user from the submitted form."""
    dto = validated_model(
        OrganizationUserCreateDTO,
        email=form.email,
        password=form.password or None,
        first_name=form.first_name,
        last_name=form.last_name,
        role=form.role,
        is_active=form.is_active,
    )
    await users_service.create(dto=dto)
    return mutation_success(
        request,
        "/management/organization/users",
        notice=ManagementNotice.USER_CREATED,
    )


@router.get("/users/{user_id}")
async def user_detail(  # noqa: PLR0913, PLR0917
    user_id: UserIdPath,
    request: Request,
    users_service: OrganizationUIUsersServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OrganizationAdminUIDep,
    notice: Annotated[str | None, Query()] = None,
) -> Response:
    """Render one user management page."""
    user = await users_service.get(user_id=user_id)
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/organization/user_form.html",
        user=OrganizationUserView.from_dto(user),
        action=f"/management/organization/users/{user_id}",
        heading="Manage organization user",
        submit_label="Save changes",
        notice=notice,
    )


@router.post("/users/{user_id}")
async def update_user(
    user_id: UserIdPath,
    request: Request,
    users_service: OrganizationFormUsersServiceDep,
    _user_ctx: OrganizationAdminFormDep,
    form: Annotated[OrganizationUserReplaceForm, Form()],
) -> Response:
    """Update the selected user."""
    dto = OrganizationUserReplaceDTO(
        email=form.email,
        first_name=form.first_name,
        last_name=form.last_name,
        role=form.role,
        is_active=form.is_active,
    )
    await users_service.replace(user_id=user_id, dto=dto)
    return mutation_success(
        request,
        f"/management/organization/users/{user_id}",
        notice=ManagementNotice.USER_UPDATED,
    )


@router.post("/users/{user_id}/invitation")
async def resend_user_invitation(
    user_id: UserIdPath,
    request: Request,
    users_service: OrganizationFormUsersServiceDep,
    _user_ctx: OrganizationAdminFormDep,
) -> Response:
    """Request another invitation for the selected user."""
    await users_service.resend_invitation(user_id=user_id)
    return mutation_success(
        request,
        f"/management/organization/users/{user_id}",
        notice=ManagementNotice.INVITATION_PROCESSED,
    )


@router.get("/users/{user_id}/delete")
async def confirm_delete_user(
    user_id: UserIdPath,
    request: Request,
    users_service: OrganizationUIUsersServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OrganizationAdminUIDep,
) -> Response:
    """Render the user-deletion confirmation."""
    user = await users_service.get(user_id=user_id)
    return await render_user_delete_confirmation(
        request,
        lifecycle_service,
        user_ctx,
        UserDeleteConfirmation(
            title="Delete organization user?",
            email=user.email,
            action=f"/management/organization/users/{user_id}/delete",
            cancel_url=f"/management/organization/users/{user_id}",
        ),
    )


@router.post("/users/{user_id}/delete")
async def delete_user(
    user_id: UserIdPath,
    request: Request,
    users_service: OrganizationFormUsersServiceDep,
    _user_ctx: OrganizationAdminFormDep,
    _confirmation: ConfirmedFormDep,
) -> Response:
    """Delete the selected user."""
    await users_service.delete(user_id=user_id)
    return mutation_success(
        request,
        "/management/organization/users",
        notice=ManagementNotice.USER_DELETED,
    )

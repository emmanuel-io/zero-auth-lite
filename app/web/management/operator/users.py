"""Server-operator user browser routes."""

from typing import Annotated

from fastapi import APIRouter, Form, Query, Request, Response
from pydantic import UUID4

from app.browser_sessions.service_dependencies import BrowserSessionLifecycleServiceDep
from app.identity.users.criteria import ServerUserSearchCriteriaDTO
from app.identity.users.dtos import ServerUserCreateDTO, ServerUserReplaceDTO
from app.identity.users.enums import OrganizationMembershipRole
from app.identity.users.specs import UserSpecs
from app.web.management.dependencies import (
    OperatorFormDep,
    OperatorFormUsersServiceDep,
    OperatorUIDep,
    OperatorUIUsersServiceDep,
)
from app.web.management.forms import ConfirmedFormDep
from app.web.management.ids import UserIdPath
from app.web.management.notices import ManagementNotice
from app.web.management.operator.forms import (
    ServerUserCreateForm,
    ServerUserReplaceForm,
)
from app.web.management.operator.views import ServerUserView
from app.web.management.pagination import pagination_links
from app.web.management.responses import (
    mutation_success,
    render_management_page,
    render_user_delete_confirmation,
    UserDeleteConfirmation,
)
from app.web.routes import ManagementPageRoute


router = APIRouter(route_class=ManagementPageRoute)


@router.get("/users")
async def users(  # noqa: PLR0913, PLR0917
    request: Request,
    service: OperatorUIUsersServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OperatorUIDep,
    q: Annotated[
        str | None, Query(max_length=UserSpecs.SEARCH_QUERY_LENGTH_MAX)
    ] = None,
    organization_id: Annotated[UUID4 | None, Query()] = None,
    role: Annotated[OrganizationMembershipRole | None, Query()] = None,
    operator: Annotated[bool | None, Query()] = None,
    active: Annotated[bool | None, Query()] = None,
    email_verified: Annotated[bool | None, Query()] = None,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    notice: Annotated[str | None, Query()] = None,
) -> Response:
    """Render the user list."""
    page = await service.search(
        criteria=ServerUserSearchCriteriaDTO(
            q=q,
            organization_id=organization_id,
            role=role.value if role is not None else None,
            operator=operator,
            active=active,
            email_verified=email_verified,
            offset=offset,
            limit=limit,
        )
    )
    filters = {
        "q": q,
        "organization_id": organization_id,
        "role": role,
        "operator": operator,
        "active": active,
        "email_verified": email_verified,
    }
    links = pagination_links(
        "/management/operator/users",
        filters=filters,
        offset=offset,
        limit=limit,
        total=page.total,
    )
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/operator/users.html",
        users=[ServerUserView.from_dto(item) for item in page.items],
        total=page.total,
        filters=filters,
        previous_url=links.previous_url,
        next_url=links.next_url,
        notice=notice,
    )


@router.get("/users/new")
async def new_user(
    request: Request,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OperatorUIDep,
    organization_id: Annotated[UUID4 | None, Query()] = None,
) -> Response:
    """Render the new-user invitation form."""
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/operator/user_form.html",
        user=None,
        action="/management/operator/users",
        heading="Invite a user",
        organization_id=organization_id,
    )


@router.post("/users")
async def create_user(
    request: Request,
    service: OperatorFormUsersServiceDep,
    _user_ctx: OperatorFormDep,
    form: Annotated[ServerUserCreateForm, Form()],
) -> Response:
    """Invite a user from the submitted form."""
    dto = ServerUserCreateDTO(
        email=form.email,
        organization_id=form.organization_id,
        first_name=form.first_name,
        last_name=form.last_name,
        role=form.role,
        is_operator=form.is_operator,
    )
    result = await service.create(dto=dto)
    return mutation_success(
        request,
        f"/management/operator/users/{result.public_id!s}",
        notice=ManagementNotice.USER_INVITED,
    )


@router.get("/users/{user_id}")
async def user_detail(  # noqa: PLR0913, PLR0917
    user_id: UserIdPath,
    request: Request,
    service: OperatorUIUsersServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OperatorUIDep,
    notice: Annotated[str | None, Query()] = None,
) -> Response:
    """Render one user management page."""
    user = await service.get(user_id=user_id)
    return await render_management_page(
        request,
        lifecycle_service,
        user_ctx,
        "management/operator/user_form.html",
        user=ServerUserView.from_dto(user),
        action=f"/management/operator/users/{user_id}",
        heading="Manage server user",
        notice=notice,
    )


@router.post("/users/{user_id}")
async def update_user(
    user_id: UserIdPath,
    request: Request,
    service: OperatorFormUsersServiceDep,
    _user_ctx: OperatorFormDep,
    form: Annotated[ServerUserReplaceForm, Form()],
) -> Response:
    """Update the selected user."""
    dto = ServerUserReplaceDTO(
        email=form.email,
        organization_id=form.organization_id,
        first_name=form.first_name,
        last_name=form.last_name,
        role=form.role,
        is_active=form.is_active,
        is_operator=form.is_operator,
        email_verified=form.email_verified,
    )
    await service.replace(user_id=user_id, dto=dto)
    return mutation_success(
        request,
        f"/management/operator/users/{user_id}",
        notice=ManagementNotice.USER_UPDATED,
    )


@router.post("/users/{user_id}/invitation")
async def resend_user_invitation(
    user_id: UserIdPath,
    request: Request,
    service: OperatorFormUsersServiceDep,
    _user_ctx: OperatorFormDep,
) -> Response:
    """Request another invitation for the selected user."""
    await service.resend_invitation(user_id=user_id)
    return mutation_success(
        request,
        f"/management/operator/users/{user_id}",
        notice=ManagementNotice.INVITATION_PROCESSED,
    )


@router.get("/users/{user_id}/delete")
async def confirm_delete_user(
    user_id: UserIdPath,
    request: Request,
    service: OperatorUIUsersServiceDep,
    lifecycle_service: BrowserSessionLifecycleServiceDep,
    user_ctx: OperatorUIDep,
) -> Response:
    """Render the user-deletion confirmation."""
    user = await service.get(user_id=user_id)
    return await render_user_delete_confirmation(
        request,
        lifecycle_service,
        user_ctx,
        UserDeleteConfirmation(
            title="Delete server user?",
            email=user.email,
            action=f"/management/operator/users/{user_id}/delete",
            cancel_url=f"/management/operator/users/{user_id}",
        ),
    )


@router.post("/users/{user_id}/delete")
async def delete_user(
    user_id: UserIdPath,
    request: Request,
    service: OperatorFormUsersServiceDep,
    _user_ctx: OperatorFormDep,
    _confirmation: ConfirmedFormDep,
) -> Response:
    """Delete the selected user."""
    await service.delete(user_id=user_id)
    return mutation_success(
        request,
        "/management/operator/users",
        notice=ManagementNotice.USER_DELETED,
    )

"""Explicit-organization security-session revocation API routes."""

from typing import Annotated

from fastapi import APIRouter, Request, Response, Security, status

from app.api.dependencies.ids import OrganizationIdPath, parse_organization_id
from app.api.error_responses import app_error_responses
from app.browser_sessions.errors import (
    CSRFCookieHeaderMismatchError,
    CSRFHeaderSessionMismatchError,
    CSRFMissingCookieError,
    CSRFMissingHeaderError,
    SessionInvalidError,
)
from app.browser_sessions.response_transport import (
    request_session_cookie_clear_on_success,
)
from app.errors import (
    ForbiddenOperationError,
    ObjectNotFoundError,
    UnauthorizedError,
)
from app.security.authentication import CurrentActorContextDep
from app.security.dtos import AuthMethod
from app.security.organization_security_session_authorization import (
    AuthorizedOrganizationSecuritySessionRevocation,
    MachineClientOrganizationAccessDeniedError,
)
from app.security.organization_security_session_dependencies import (
    OrganizationSecuritySessionAuthorizationServiceDep,
)
from app.security.permissions import Permission
from app.security.session_revocation_dependencies import SecuritySessionRevocationDep


router = APIRouter(prefix="/organizations")
ORGANIZATION_SESSION_REVOCATION_REASON = "organization_sessions_revoked"


async def authorize_organization_session_revocation(
    organization_id: OrganizationIdPath,
    principal: CurrentActorContextDep,
    authorization_service: OrganizationSecuritySessionAuthorizationServiceDep,
) -> AuthorizedOrganizationSecuritySessionRevocation:
    """Authorize one operator or machine client for a target organization."""
    return await authorization_service.authorize(
        organization_public_id=parse_organization_id(organization_id),
        principal=principal,
    )


AuthorizedOrganizationSessionRevocationDep = Annotated[
    AuthorizedOrganizationSecuritySessionRevocation,
    Security(
        authorize_organization_session_revocation,
        scopes=[Permission.USERS_WRITE.value],
    ),
]


@router.delete(
    "/{organization_id}/sessions",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke all sessions for one organization",
    description=(
        "Revoke all browser and OAuth2 sessions attributed to an organization. "
        "Server operators require users:write. OAuth2 client-credentials "
        "callers also require users:write and current machine access to the "
        "target organization. A 404 intentionally does not distinguish a missing "
        "organization from one outside a machine client's assignments."
    ),
    responses=app_error_responses(
        UnauthorizedError,
        SessionInvalidError,
        ForbiddenOperationError,
        MachineClientOrganizationAccessDeniedError,
        CSRFMissingCookieError,
        CSRFMissingHeaderError,
        CSRFCookieHeaderMismatchError,
        CSRFHeaderSessionMismatchError,
        ObjectNotFoundError,
        descriptions={
            401: "Authentication is missing or invalid.",
            403: (
                "The principal lacks operator authority or users:write, or the "
                "machine client has no organization access policy; browser sessions "
                "must also pass CSRF validation."
            ),
            404: (
                "The organization is missing or is not assigned to the machine client; "
                "these cases are intentionally indistinguishable."
            ),
        },
    )
    | {204: {"description": "All organization sessions were revoked."}},
)
async def revoke_organization_sessions(
    request: Request,
    organization_id: OrganizationIdPath,
    authorization: AuthorizedOrganizationSessionRevocationDep,
    revocation_service: SecuritySessionRevocationDep,
) -> Response:
    """Revoke all persisted session authority for one organization."""
    _ = organization_id
    await revocation_service.revoke_organization_security_sessions(
        organization_id=authorization.organization_id,
        reason=ORGANIZATION_SESSION_REVOCATION_REASON,
    )
    if (
        authorization.principal.auth_method == AuthMethod.SESSION
        and authorization.principal.organization_id == authorization.organization_id
    ):
        request_session_cookie_clear_on_success(request)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

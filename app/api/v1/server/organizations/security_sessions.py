"""Explicit-organization security-session revocation API routes."""

from typing import Annotated

from fastapi import APIRouter, Request, Response, Security, status

from app.api.dependencies.ids import OrganizationIdPath
from app.api.error_responses import app_error_responses
from app.browser_sessions.enums import BrowserSessionRevocationReason
from app.browser_sessions.errors import (
    BrowserSessionInvalidError,
    CSRF_ERRORS,
)
from app.browser_sessions.response_transport import (
    request_session_cookie_clear_on_success,
)
from app.core.errors.common import (
    ForbiddenOperationError,
    ObjectNotFoundError,
    UnauthorizedError,
)
from app.security.authentication import CurrentActorContextDep
from app.security.organization_security_session_authorization import (
    AuthorizedOrganizationSecuritySessionRevocation,
    MachineClientOrganizationAccessDeniedError,
)
from app.security.organization_security_session_dependencies import (
    OrganizationSecuritySessionAuthorizationServiceDep,
)
from app.security.permissions import Permission
from app.security.principals import AuthenticationMechanism
from app.security.session_revocation_dependencies import SecuritySessionRevocationDep


router = APIRouter(prefix="/organizations")


async def authorize_organization_session_revocation(
    organization_id: OrganizationIdPath,
    principal: CurrentActorContextDep,
    authorization_service: OrganizationSecuritySessionAuthorizationServiceDep,
) -> AuthorizedOrganizationSecuritySessionRevocation:
    """Authorize one operator or machine client for a target organization."""
    return await authorization_service.authorize(
        organization_public_id=organization_id,
        principal=principal,
    )


AuthorizedOrganizationSessionRevocationDep = Annotated[
    AuthorizedOrganizationSecuritySessionRevocation,
    Security(
        authorize_organization_session_revocation,
        scopes=[Permission.SESSIONS_WRITE.value],
    ),
]


@router.delete(
    "/{organization_id}/sessions",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke all sessions for one organization",
    description=(
        "Revoke all browser and OAuth2 sessions attributed to an organization. "
        "Server operators require sessions:write. OAuth2 client-credentials "
        "callers also require sessions:write and current machine access to the "
        "target organization. A 404 intentionally does not distinguish a missing "
        "organization from one outside a machine client's assignments."
    ),
    responses=app_error_responses(
        UnauthorizedError,
        BrowserSessionInvalidError,
        ForbiddenOperationError,
        MachineClientOrganizationAccessDeniedError,
        *CSRF_ERRORS,
        ObjectNotFoundError,
        descriptions={
            401: "Authentication is missing or invalid.",
            403: (
                "The principal lacks operator authority or sessions:write, or the "
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
        browser_reason=BrowserSessionRevocationReason.ORGANIZATION_SESSIONS_REVOKED,
    )
    if (
        authorization.principal.authentication_mechanism
        is AuthenticationMechanism.BROWSER_SESSION
        and authorization.principal.organization_id == authorization.organization_id
    ):
        request_session_cookie_clear_on_success(request)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

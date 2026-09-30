"""Authorization dependencies for OAuth2 client administration routes."""

from typing import Annotated

from fastapi import Security

from app.security.authorization import require_operator_permission
from app.security.permissions import Permission
from app.security.principals import UserPrincipalContext


OperatorOAuth2ClientsReadDep = Annotated[
    UserPrincipalContext,
    Security(
        require_operator_permission(Permission.OAUTH2_CLIENTS_READ),
        scopes=[Permission.OAUTH2_CLIENTS_READ.value],
    ),
]
OperatorOAuth2ClientsWriteDep = Annotated[
    UserPrincipalContext,
    Security(
        require_operator_permission(Permission.OAUTH2_CLIENTS_WRITE),
        scopes=[Permission.OAUTH2_CLIENTS_WRITE.value],
    ),
]

"""Authorization checks for OAuth2 client administration services."""

from app.errors import ForbiddenOperationError
from app.security.dtos import UserPrincipalContext


def require_operator(operator_ctx: UserPrincipalContext) -> None:
    """Require server-operator authority at the service boundary."""
    if not operator_ctx.is_operator:
        raise ForbiddenOperationError

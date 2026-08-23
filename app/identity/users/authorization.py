"""Authorization decisions for security-sensitive user mutations."""

from app.errors import ForbiddenOperationError


def require_organization_managed_target(*, target_is_operator: bool) -> None:
    """Keep operator accounts outside organization-scoped mutation APIs."""
    if target_is_operator:
        raise ForbiddenOperationError

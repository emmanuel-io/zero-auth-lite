"""Dependency injection for single-use workflow tokens."""

from typing import Annotated

from fastapi import Depends

from app.db.dependencies import DbSessionDep, DbSessionFactoryDep
from app.password.dependencies import PasswordHasherDep
from app.security.session_revocation_dependencies import SecuritySessionRevocationDep
from app.settings.dependencies import WorkflowTokenSettingsDep
from app.workflow_tokens.confirmation_service import WorkflowTokenConfirmationService
from app.workflow_tokens.service import WorkflowTokenService


def get_workflow_token_service(
    db_session: DbSessionDep,
    settings: WorkflowTokenSettingsDep,
) -> WorkflowTokenService:
    """Provide the single-use workflow-token service."""
    return WorkflowTokenService(
        db_session=db_session,
        settings=settings,
    )


WorkflowTokenServiceDep = Annotated[
    WorkflowTokenService, Depends(get_workflow_token_service)
]


def get_workflow_token_confirmation_service(
    workflow_token_service: WorkflowTokenServiceDep,
    db_session: DbSessionDep,
    security_revocation: SecuritySessionRevocationDep,
    password_hasher: PasswordHasherDep,
    session_factory: DbSessionFactoryDep,
) -> WorkflowTokenConfirmationService:
    """Build the app-owned workflow-token confirmation service."""
    return WorkflowTokenConfirmationService(
        workflow_token_service=workflow_token_service,
        db_session=db_session,
        security_revocation=security_revocation,
        password_hasher=password_hasher,
        session_factory=session_factory,
    )


WorkflowTokenConfirmationServiceDep = Annotated[
    WorkflowTokenConfirmationService,
    Depends(get_workflow_token_confirmation_service),
]

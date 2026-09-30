"""Shared bounded inputs for server-rendered authentication forms."""

from typing import Annotated

from fastapi import Form, Query

from app.identity.organizations.specs import OrganizationSpecs
from app.identity.users.specs import UserSpecs
from app.password.validation import PasswordInput
from app.workflow_tokens.specs import WorkflowTokenSpecs


type EmailForm = Annotated[str, Form(max_length=UserSpecs.EMAIL_LENGTH_MAX)]
type FirstNameForm = Annotated[str, Form(max_length=UserSpecs.FIRST_NAME_LENGTH_MAX)]
type LastNameForm = Annotated[str, Form(max_length=UserSpecs.LAST_NAME_LENGTH_MAX)]
type OrganizationNameForm = Annotated[
    str, Form(max_length=OrganizationSpecs.NAME_LENGTH_MAX)
]
type PasswordForm = Annotated[PasswordInput, Form()]
type WorkflowTokenForm = Annotated[
    str,
    Form(
        min_length=WorkflowTokenSpecs.RAW_TOKEN_LENGTH_MIN,
        max_length=WorkflowTokenSpecs.RAW_TOKEN_LENGTH_MAX,
    ),
]
type WorkflowTokenQuery = Annotated[
    str,
    Query(
        min_length=WorkflowTokenSpecs.RAW_TOKEN_LENGTH_MIN,
        max_length=WorkflowTokenSpecs.RAW_TOKEN_LENGTH_MAX,
    ),
]

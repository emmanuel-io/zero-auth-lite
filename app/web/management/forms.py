"""Shared validation for management HTML forms."""

from typing import Annotated, TypeAlias

from fastapi import Depends, Form
from pydantic import AfterValidator, BaseModel, ConfigDict


class ManagementForm(BaseModel):
    """Immutable fields shared by management form payloads."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    csrf_token: str | None = None


def split_non_empty_lines(value: str) -> list[str]:
    """Split a multiline form value and discard blank lines."""
    return [line.strip() for line in value.splitlines() if line.strip()]


def require_confirmation(value: bool) -> bool:  # noqa: FBT001
    """Require an explicit affirmative value for a destructive action."""
    if not value:
        msg = "Confirmation is required."
        raise ValueError(msg)
    return value


# FastAPI inspects this alias at runtime when building the form contract and
# does not currently resolve its PEP 695 ``TypeAliasType`` form.
_ConfirmedFormValue: TypeAlias = Annotated[  # noqa: UP040
    bool,
    Form(),
    AfterValidator(require_confirmation),
]


def require_confirmed_form(confirm: _ConfirmedFormValue) -> None:
    """Validate the affirmative form field before a destructive action."""


ConfirmedFormDep: TypeAlias = Annotated[  # noqa: UP040
    None, Depends(require_confirmed_form)
]

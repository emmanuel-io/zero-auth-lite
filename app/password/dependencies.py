"""FastAPI dependencies for password hashing."""

from typing import Annotated, cast

from fastapi import Depends, Request

from app.password.protocols import PasswordHasherProtocol


def get_password_hasher(request: Request) -> PasswordHasherProtocol:
    """Return the password hasher configured for this server."""
    return cast("PasswordHasherProtocol", request.app.state.password_hasher)


PasswordHasherDep = Annotated[PasswordHasherProtocol, Depends(get_password_hasher)]

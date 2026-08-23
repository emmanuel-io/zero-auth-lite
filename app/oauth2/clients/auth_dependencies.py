# ruff: noqa: PLR0913, TC001, TC002
"""FastAPI dependency wrappers for OAuth2 client authentication."""

from __future__ import annotations

import base64
from logging import getLogger
from typing import Annotated

from fastapi import Depends, Form, Request
from fastapi.security import HTTPBasicCredentials

from app.db.dependencies import DbSessionDep
from app.oauth2.clients.auth import (
    authenticate_token_client,
    ClientAuth,
)
from app.oauth2.errors import InvalidClientError
from app.oauth2.grants.dependencies import OAuth2ClientBasicDep
from app.oauth2.specs import OAuth2Specs
from app.password.dependencies import PasswordHasherDep
from app.settings.dependencies import OAuth2SettingsDep


logger = getLogger(__name__)


def authorization_header(credentials: HTTPBasicCredentials | None) -> str | None:
    """Recreate a Basic header for the framework-independent auth helper."""
    if credentials is None:
        return None
    payload = f"{credentials.username}:{credentials.password}".encode()
    return f"Basic {base64.b64encode(payload).decode()}"


async def form_credential(
    request: Request,
    *,
    name: str,
    parsed_value: str | None,
) -> str | None:
    """Preserve the presence of an empty typed OAuth2 credential field."""
    if parsed_value is not None:
        return parsed_value
    raw_value = (await request.form()).get(name)
    return raw_value if isinstance(raw_value, str) else None


async def authenticate_token_client_for_grant(
    *,
    request: Request,
    db_session: DbSessionDep,
    settings: OAuth2SettingsDep,
    password_hasher: PasswordHasherDep,
    basic_credentials: OAuth2ClientBasicDep,
    grant_type: Annotated[
        str | None, Form(max_length=OAuth2Specs.GRANT_TYPE_LENGTH_MAX)
    ] = None,
    client_id: Annotated[
        str | None, Form(max_length=OAuth2Specs.CLIENT_ID_LENGTH_MAX)
    ] = None,
    client_secret: Annotated[
        str | None, Form(max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
    ] = None,
) -> ClientAuth | None:
    """Authenticate OAuth2 clients only for grants that currently require it."""
    authorization = authorization_header(basic_credentials)
    client_id = await form_credential(
        request,
        name="client_id",
        parsed_value=client_id,
    )
    client_secret = await form_credential(
        request,
        name="client_secret",
        parsed_value=client_secret,
    )
    if grant_type is not None and not settings.is_grant_enabled(grant_type):
        return None
    if grant_type == "refresh_token" and not authorization and not client_id:
        return None
    if grant_type not in {
        "authorization_code",
        "refresh_token",
        "client_credentials",
        "urn:ietf:params:oauth:grant-type:device_code",
    }:
        return None
    return await authenticate_token_client(
        db_session=db_session,
        authorization=authorization,
        client_id=client_id,
        client_secret=client_secret,
        allow_client_secret_post=settings.allow_client_secret_post,
        password_hasher=password_hasher,
    )


async def authenticate_revoke_client(
    *,
    request: Request,
    db_session: DbSessionDep,
    settings: OAuth2SettingsDep,
    password_hasher: PasswordHasherDep,
    basic_credentials: OAuth2ClientBasicDep,
    client_id: Annotated[
        str | None, Form(max_length=OAuth2Specs.CLIENT_ID_LENGTH_MAX)
    ] = None,
    client_secret: Annotated[
        str | None, Form(max_length=OAuth2Specs.PROTOCOL_VALUE_LENGTH_MAX)
    ] = None,
) -> ClientAuth:
    """Authenticate or identify an OAuth2 client for revoke/introspect routes."""
    authorization = authorization_header(basic_credentials)
    client_id = await form_credential(
        request,
        name="client_id",
        parsed_value=client_id,
    )
    client_secret = await form_credential(
        request,
        name="client_secret",
        parsed_value=client_secret,
    )
    return await authenticate_token_client(
        db_session=db_session,
        authorization=authorization,
        client_id=client_id,
        client_secret=client_secret,
        allow_client_secret_post=settings.allow_client_secret_post,
        password_hasher=password_hasher,
    )


async def authenticate_introspection_client(
    client_auth: Annotated[ClientAuth, Depends(authenticate_revoke_client)],
) -> ClientAuth:
    """Require confidential authentication for token introspection."""
    if client_auth.method == "public":
        raise InvalidClientError
    return client_auth

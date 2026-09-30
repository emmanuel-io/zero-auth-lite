"""FastAPI dependency wrappers for OAuth2 client authentication."""

from __future__ import annotations

from typing import Annotated
from urllib.parse import unquote_plus

from fastapi import Depends, Form, HTTPException, Request, Security
from fastapi.security import HTTPBasic, HTTPBasicCredentials

# FastAPI resolves dependency annotations from module globals at runtime.
from app.db.dependencies import DbSessionDep  # noqa: TC001
from app.oauth2.clients.auth import (
    authenticate_token_client,
    BasicClientCredentials,
    ClientAuth,
)
from app.oauth2.errors import InvalidClientError
from app.oauth2.specs import OAuth2Specs
from app.password.dependencies import PasswordHasherDep  # noqa: TC001
from app.settings.dependencies import OAuth2SettingsDep  # noqa: TC001


class OAuth2ClientHTTPBasic(HTTPBasic):
    """Translate malformed Basic transport into an OAuth2 client error."""

    async def __call__(  # type: ignore[override]
        self, request: Request
    ) -> HTTPBasicCredentials | None:
        """Extract optional credentials without leaking FastAPI's error envelope."""
        try:
            return await super().__call__(request)
        except HTTPException as exc:
            raise InvalidClientError(challenge_basic=True) from exc


oauth2_client_basic = OAuth2ClientHTTPBasic(
    auto_error=False,
    scheme_name="OAuth2ClientBasic",
    description="OAuth2 confidential-client authentication.",
)
OAuth2ClientBasicDep = Annotated[
    HTTPBasicCredentials | None,
    Security(oauth2_client_basic),
]


def decode_basic_credentials(
    credentials: HTTPBasicCredentials | None,
) -> BasicClientCredentials | None:
    """Decode RFC 6749 form-encoded Basic credential components."""
    if credentials is None:
        return None
    return BasicClientCredentials(
        client_id=unquote_plus(credentials.username),
        client_secret=unquote_plus(credentials.password),
    )


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


# FastAPI keeps protocol transport fields explicit for validation and OpenAPI.
async def authenticate_token_client_for_grant(  # noqa: PLR0913
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
    decoded_basic_credentials = decode_basic_credentials(basic_credentials)
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
    if (
        grant_type == "refresh_token"
        and decoded_basic_credentials is None
        and not client_id
    ):
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
        basic_credentials=decoded_basic_credentials,
        client_id=client_id,
        client_secret=client_secret,
        allow_client_secret_post=settings.allow_client_secret_post,
        password_hasher=password_hasher,
    )


# FastAPI keeps protocol transport fields explicit for validation and OpenAPI.
async def authenticate_revoke_client(  # noqa: PLR0913
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
    decoded_basic_credentials = decode_basic_credentials(basic_credentials)
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
        basic_credentials=decoded_basic_credentials,
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

# ruff: noqa: TC001, TC002
"""Reusable OAuth2 client authentication helpers for protocol endpoints.

Implements RFC 6749 §2.3.1 and RFC 7009:
- Confidential clients: HTTP Basic (client_secret_basic), or body credentials
  (client_secret_post) when enabled by server policy.
- Public clients: client_id in the form body.
- /token: if Authorization is present, MUST NOT include client_id/client_secret in body.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from logging import getLogger
from typing import Literal

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.oauth2_client import OAuth2ClientDB
from app.oauth2.clients.dtos import OAuth2ClientReadDTO
from app.oauth2.errors import InvalidClientError, OAuth2ProtocolError
from app.password.async_hashing import verify_password
from app.password.protocols import PasswordHasherProtocol


logger = getLogger(__name__)


@dataclass(slots=True, frozen=True)
class ClientAuth:
    """Resolved client authentication outcome."""

    client: OAuth2ClientReadDTO
    method: Literal["basic", "post", "public"]

    @property
    def client_id(self) -> str:
        """Return the resolved client's public identifier."""
        return self.client.client_id


async def lock_and_reload_token_client(
    db_session: AsyncSession, client_auth: ClientAuth | None
) -> ClientAuth | None:
    """Lock and reload a token client after credential verification.

    Confidential-secret verification runs outside the SQLite transaction. The
    no-op update starts the short token-issuance write transaction, then the
    fresh row prevents a concurrent secret rotation or policy reduction from
    issuing a token from stale client state.
    """
    if client_auth is None:
        return None

    await db_session.commit()
    locked_client_id = await db_session.scalar(
        text(
            "UPDATE oauth2_client SET id = id WHERE client_id = :client_id RETURNING id"
        ),
        {"client_id": client_auth.client_id},
    )
    if locked_client_id is None:
        raise InvalidClientError(challenge_basic=client_auth.method == "basic")

    row = await db_session.scalar(
        select(OAuth2ClientDB)
        .where(OAuth2ClientDB.id == locked_client_id)
        .execution_options(populate_existing=True)
    )
    current = OAuth2ClientReadDTO.model_validate(row) if row is not None else None
    expected_secret_hash = client_auth.client.client_secret
    if (
        current is None
        or not current.is_active
        or current.is_confidential != client_auth.client.is_confidential
        or (
            client_auth.method in {"basic", "post"}
            and current.client_secret != expected_secret_hash
        )
    ):
        raise InvalidClientError(challenge_basic=client_auth.method == "basic")
    return ClientAuth(client=current, method=client_auth.method)


def _parse_basic_header(authorization: str) -> tuple[str, str]:
    """Parse `Authorization: Basic base64(client_id:client_secret)`.

    Args:
        authorization: Full Authorization header value.

    Returns:
        Tuple (client_id, client_secret).

    Raises:
        InvalidClientError: If the header is malformed or unsupported.
    """
    if not authorization.startswith("Basic "):
        raise InvalidClientError(challenge_basic=True)
    try:
        payload = authorization.split(" ", 1)[1]
        decoded = base64.b64decode(payload, validate=True).decode("utf-8")
        client_id, client_secret = decoded.split(":", 1)
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise InvalidClientError(challenge_basic=True) from exc
    else:
        if not client_id:
            logger.error("empty client_id in Basic auth")
            raise InvalidClientError(challenge_basic=True)
        return client_id, client_secret


def _form_text(value: object | None) -> str | None:
    """Return a form value as text when it is a simple string.

    Args:
        value (object | None): Raw value read from a request form.

    Returns:
        str | None: Text value, or None for missing/non-text values.
    """
    return value if isinstance(value, str) else None


async def _get_client_auth_basic(
    db_session: AsyncSession,
    authorization: str,
    password_hasher: PasswordHasherProtocol,
) -> ClientAuth:
    """Authenticate a confidential client from an HTTP Basic header.

    The endpoint boundary rejects requests that combine Basic and body
    credentials before calling this helper.

    Returns:
        ClientAuth: The authenticated confidential client and Basic method.

    Raises:
        InvalidClientError: If the header or client credentials are invalid.
    """
    basic_client_id, basic_client_secret = _parse_basic_header(authorization)
    row = await db_session.scalar(
        select(OAuth2ClientDB).where(OAuth2ClientDB.client_id == basic_client_id)
    )
    client = OAuth2ClientReadDTO.model_validate(row) if row is not None else None
    # Client authentication is a route-boundary read. Release SQLite's read
    # transaction before the deliberately expensive secret verification.
    await db_session.commit()
    if (
        client is None
        or not client.is_active
        or not client.is_confidential
        or client.client_secret is None
        or not await verify_password(
            password_hasher,
            password=basic_client_secret,
            password_hash=client.client_secret,
        )
    ):
        logger.warning(
            "OAuth2 client authentication failed client_id=%s method=basic",
            basic_client_id,
        )
        raise InvalidClientError(challenge_basic=True)
    return ClientAuth(
        client=client,
        method="basic",
    )


# Typed header and form credentials remain distinct because OAuth2 assigns
# different precedence and validation rules to each transport.
async def authenticate_token_client(  # noqa: PLR0913
    *,
    db_session: AsyncSession,
    password_hasher: PasswordHasherProtocol,
    authorization: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    allow_client_secret_post: bool = True,
) -> ClientAuth:
    """Authenticate/identify OAuth2 client for the /token endpoint.

    Rules:
        - If Authorization present → use Basic (confidential).
        - Else → require client_id in form (public OR client_secret_post).
        - If both Basic and form creds → 400 invalid_request (RFC).
        - If client_secret_post is disabled and a secret is sent in body
          → 400 invalid_request.

    Returns:
        ClientAuth describing the authenticated/identified client.

    Raises:
        OAuth2ProtocolError: If the request is invalid.
    """
    if authorization is not None and (
        client_id is not None or client_secret is not None
    ):
        raise OAuth2ProtocolError(
            error="invalid_request",
            error_description="Do not send credentials in both header and body.",
        )

    if authorization is not None:
        return await _get_client_auth_basic(
            db_session=db_session,
            authorization=authorization,
            password_hasher=password_hasher,
        )

    if not client_id:
        raise OAuth2ProtocolError(
            error="invalid_request",
            error_description=(
                "client_id required in body when Authorization header is absent."
            ),
        )

    row = await db_session.scalar(
        select(OAuth2ClientDB).where(OAuth2ClientDB.client_id == client_id)
    )
    client = OAuth2ClientReadDTO.model_validate(row) if row is not None else None
    if client is None:
        logger.warning(
            (
                "OAuth2 client authentication failed client_id=%s method=body "
                "reason=unknown_client"
            ),
            client_id,
        )
        raise InvalidClientError
    if not client.is_active:
        logger.warning(
            (
                "OAuth2 client authentication failed client_id=%s method=body "
                "reason=inactive_client"
            ),
            client_id,
        )
        raise InvalidClientError

    if client_secret is not None:
        if not allow_client_secret_post:
            logger.warning(
                (
                    "OAuth2 client authentication rejected client_id=%s method=post "
                    "reason=client_secret_post_disabled"
                ),
                client_id,
            )
            raise OAuth2ProtocolError(error="invalid_request")
        # Public-client identification stays in the grant transaction. Only
        # confidential secret verification needs the early read boundary.
        await db_session.commit()
        if (
            not client.is_confidential
            or client.client_secret is None
            or not await verify_password(
                password_hasher,
                password=client_secret,
                password_hash=client.client_secret,
            )
        ):
            logger.warning(
                "OAuth2 client authentication failed client_id=%s method=post",
                client_id,
            )
            raise InvalidClientError
        return ClientAuth(
            client=client,
            method="post",
        )

    # A body client_id without a secret is valid only for a public client.
    if client.is_confidential:
        logger.warning(
            (
                "OAuth2 client authentication failed client_id=%s method=public "
                "reason=confidential_client_without_secret"
            ),
            client_id,
        )
        raise InvalidClientError
    return ClientAuth(client=client, method="public")

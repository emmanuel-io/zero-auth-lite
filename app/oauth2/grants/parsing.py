"""Explicit parsing helpers for supported OAuth2 token grants."""

from fastapi import status
from pydantic import ValidationError

from app.oauth2.errors import OAuth2ProtocolError
from app.oauth2.grants.request import (
    AuthorizationCodeGrantRequest,
    ClientCredentialsGrantRequest,
    DeviceCodeGrantRequest,
    GrantRequest,
    RefreshTokenGrantRequest,
)
from app.oauth2.settings import OAuth2GrantType


def _unsupported_grant_type() -> GrantRequest:
    """Raise the standard unsupported_grant_type protocol error."""
    raise OAuth2ProtocolError(error="unsupported_grant_type")


def _require_text(mapping: dict[str, object], key: str) -> str:
    """Return one required text form/query field or raise invalid_request."""
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise OAuth2ProtocolError(
            error="invalid_request",
            status_code=status.HTTP_400_BAD_REQUEST,
            error_description=f"Missing required parameter: {key}.",
        )
    return value


def _optional_text(mapping: dict[str, object], key: str) -> str | None:
    """Return one optional text form/query field."""
    value = mapping.get(key)
    return value if isinstance(value, str) and value != "" else None


def parse_token_grant(fields: dict[str, object]) -> GrantRequest:
    """Parse one supported token grant without leaking 422 responses."""
    grant_type = _optional_text(fields, "grant_type")
    if grant_type is None:
        raise OAuth2ProtocolError(error="invalid_request")

    try:
        match grant_type:
            case "authorization_code":
                return AuthorizationCodeGrantRequest(
                    grant_type=OAuth2GrantType.authorization_code,
                    code=_require_text(fields, "code"),
                    redirect_uri=_require_text(fields, "redirect_uri"),
                    code_verifier=_require_text(fields, "code_verifier"),
                    client_id=_optional_text(fields, "client_id"),
                    client_secret=_optional_text(fields, "client_secret"),
                )
            case "refresh_token":
                return RefreshTokenGrantRequest(
                    grant_type=OAuth2GrantType.refresh_token,
                    refresh_token=_require_text(fields, "refresh_token"),
                    client_id=_optional_text(fields, "client_id"),
                    client_secret=_optional_text(fields, "client_secret"),
                    scope=_optional_text(fields, "scope"),
                )
            case "client_credentials":
                return ClientCredentialsGrantRequest(
                    grant_type=OAuth2GrantType.client_credentials,
                    client_id=_optional_text(fields, "client_id"),
                    client_secret=_optional_text(fields, "client_secret"),
                    scope=_optional_text(fields, "scope"),
                )
            case "urn:ietf:params:oauth:grant-type:device_code":
                return DeviceCodeGrantRequest(
                    grant_type=OAuth2GrantType.device_code,
                    device_code=_require_text(fields, "device_code"),
                    client_id=_optional_text(fields, "client_id"),
                    client_secret=_optional_text(fields, "client_secret"),
                )
            case _:
                return _unsupported_grant_type()
    except OAuth2ProtocolError:
        raise
    except ValidationError as exc:
        raise OAuth2ProtocolError(error="invalid_request") from exc

"""Tests for OAuth2 dependency provider helpers."""

from types import SimpleNamespace

import pytest
from app.oauth2.error_handler import oauth2_protocol_error_handler
from app.oauth2.errors import OAuth2ProtocolError
from fastapi import status


pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_oauth2_protocol_error_handler_omits_optional_description() -> None:
    """Assert OAuth2 errors serialize without optional description when absent."""
    response = await oauth2_protocol_error_handler(
        request=SimpleNamespace(),  # type: ignore[arg-type]
        exc=OAuth2ProtocolError(error="invalid_request"),
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert b"error_description" not in response.body
    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.asyncio
async def test_oauth2_protocol_error_handler_includes_description() -> None:
    """Assert OAuth2 errors serialize optional descriptions when present."""
    response = await oauth2_protocol_error_handler(
        request=SimpleNamespace(),  # type: ignore[arg-type]
        exc=OAuth2ProtocolError(
            error="invalid_request",
            error_description="Missing redirect_uri",
        ),
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert b"error_description" in response.body

"""Shared HTTP-boundary tests for OAuth2 client authentication."""

import httpx
import pytest
from fastapi import status

from tests.identifiers import deterministic_uuid


pytestmark = pytest.mark.api


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "data"),
    [
        ("/oauth2/token", {"grant_type": "client_credentials"}),
        ("/oauth2/revoke", {"token": "opaque-token"}),
        ("/oauth2/introspect", {"token": "opaque-token"}),
        (
            "/oauth2/device_authorization",
            {"client_id": str(deterministic_uuid("device-client"))},
        ),
    ],
)
@pytest.mark.parametrize(
    "authorization",
    ["Basic !!!", "Basic bm8tY29sb24=", "Basic /w==", "Basic"],
)
async def test_malformed_basic_uses_oauth2_error_contract(
    client: httpx.AsyncClient,
    path: str,
    data: dict[str, str],
    authorization: str,
) -> None:
    """Translate malformed Basic transport before application error handling."""
    response = await client.post(
        path,
        data=data,
        headers={"Authorization": authorization},
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == {"error": "invalid_client"}
    assert response.headers["www-authenticate"] == 'Basic realm="oauth2/token"'

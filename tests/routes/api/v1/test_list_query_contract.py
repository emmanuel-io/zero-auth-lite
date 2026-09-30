"""Cross-surface contract tests for API list query parameters."""

import httpx
import pytest
from fastapi import status

from tests.fixtures.auth import UserCredentials
from tests.routes.api.helpers import login_headers


pytestmark = pytest.mark.api


@pytest.mark.asyncio
@pytest.mark.negative
@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/organization/users",
        "/api/v1/server/users",
        "/api/v1/organization/oauth2/sessions",
        "/api/v1/me/oauth2/sessions",
        "/api/v1/me/sessions",
        "/api/v1/server/oauth2/clients",
        "/api/v1/server/organizations",
    ],
)
async def test_api_lists_reject_unknown_query_parameters(
    path: str,
    client: httpx.AsyncClient,
    verified_user_credentials: UserCredentials,
) -> None:
    """Reject misspelled or unsupported query parameters consistently."""
    headers = await login_headers(client, verified_user_credentials)

    response = await client.get(path, params={"unexpected": "value"}, headers=headers)

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

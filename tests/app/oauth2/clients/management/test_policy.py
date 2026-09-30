"""Branch tests for OAuth2 client policy decisions."""

import pytest
from app.oauth2.clients.management.errors import (
    InvalidOAuth2ClientPayloadError,
    OAuth2ClientManagementErrorReason,
)
from app.oauth2.clients.management.policy import OAuth2ClientPolicy
from app.oauth2.grants.types import OAuth2GrantType
from app.oauth2.settings import OAuth2Settings


pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    ("grant_types", "redirect_uris", "confidential", "consent"),
    [
        ([], [], True, True),
        (["unknown"], [], True, True),
        ([OAuth2GrantType.AUTHORIZATION_CODE], [], True, True),
        ([OAuth2GrantType.CLIENT_CREDENTIALS], [], False, True),
        ([OAuth2GrantType.REFRESH_TOKEN], [], True, True),
        (
            [OAuth2GrantType.AUTHORIZATION_CODE],
            ["https://client.example/callback"],
            False,
            False,
        ),
        (
            [OAuth2GrantType.AUTHORIZATION_CODE],
            ["https://client.example/callback#fragment"],
            True,
            True,
        ),
        (
            [OAuth2GrantType.AUTHORIZATION_CODE],
            ["http://client.example/callback"],
            True,
            True,
        ),
        (
            [OAuth2GrantType.AUTHORIZATION_CODE],
            ["https://client.example/callback", "https://client.example/callback"],
            True,
            True,
        ),
    ],
)
def test_client_policy_rejects_each_invalid_configuration(
    grant_types: list[str],
    redirect_uris: list[str],
    confidential: bool,  # noqa: FBT001
    consent: bool,  # noqa: FBT001
) -> None:
    """Cover each client-policy rejection independently."""
    policy = OAuth2ClientPolicy(
        OAuth2Settings(
            authorization_code_enabled=True,
            client_credentials_enabled=True,
            refresh_token_enabled=True,
        )
    )
    with pytest.raises(InvalidOAuth2ClientPayloadError):
        policy.validate(
            grant_types=grant_types,
            redirect_uris=redirect_uris,
            is_confidential=confidential,
            requires_consent=consent,
        )


def test_client_policy_accepts_each_supported_flow() -> None:
    """Accept a composable authorization-code and refresh configuration."""
    OAuth2ClientPolicy(
        OAuth2Settings(
            authorization_code_enabled=True,
            refresh_token_enabled=True,
        )
    ).validate(
        grant_types=[
            OAuth2GrantType.AUTHORIZATION_CODE,
            OAuth2GrantType.REFRESH_TOKEN,
        ],
        redirect_uris=["https://client.example/callback"],
        is_confidential=True,
        requires_consent=True,
    )


def test_client_policy_keeps_reason_and_context_separate() -> None:
    """Keep diagnostic grant names out of the stable publishable reason."""
    policy = OAuth2ClientPolicy(OAuth2Settings())

    with pytest.raises(InvalidOAuth2ClientPayloadError) as caught:
        policy.validate(
            grant_types=["unknown_b", "unknown_a"],
            redirect_uris=[],
            is_confidential=True,
            requires_consent=True,
        )

    assert (
        caught.value.reason is OAuth2ClientManagementErrorReason.UNSUPPORTED_GRANT_TYPES
    )
    assert caught.value.context == ("unknown_a", "unknown_b")

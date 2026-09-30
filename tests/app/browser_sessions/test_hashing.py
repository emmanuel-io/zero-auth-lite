"""Tests for privacy-preserving browser-session hashing."""

from collections.abc import Callable

import pytest
from app.browser_sessions.hashing import (
    hash_auth_identifier,
    hash_configured_session_id,
    hash_session_id,
    hash_session_ip,
    hash_session_user_agent,
)
from app.browser_sessions.settings import BrowserSessionSettings
from pydantic import SecretStr


pytestmark = pytest.mark.unit
HASH_DOMAIN_COUNT = 4


def test_hash_configured_session_id_uses_the_session_secret() -> None:
    """Bind stored session identifiers to the configured HMAC secret."""
    settings = BrowserSessionSettings(hash_secret=SecretStr("s" * 32))

    assert hash_configured_session_id(session_id="raw-session", settings=settings) == (
        hash_session_id(session_id="raw-session", secret="s" * 32)
    )


def test_hash_domains_do_not_correlate_the_same_value() -> None:
    """Produce distinct digests for distinct privacy contexts."""
    value = "same-value"
    secret = "s" * 32

    digests = {
        hash_session_id(session_id=value, secret=secret),
        hash_auth_identifier(value=value, secret=secret),
        hash_session_ip(value=value, secret=secret),
        hash_session_user_agent(value=value, secret=secret),
    }

    assert len(digests) == HASH_DOMAIN_COUNT


def test_auth_identifier_hash_normalizes_case_and_whitespace() -> None:
    """Keep equivalent submitted email identifiers on one log-safe digest."""
    secret = "s" * 32

    assert hash_auth_identifier(value=" User@Example.com ", secret=secret) == (
        hash_auth_identifier(value="user@example.com", secret=secret)
    )


@pytest.mark.parametrize("hash_value", [hash_session_ip, hash_session_user_agent])
def test_optional_session_context_hashes_empty_values_as_none(
    hash_value: Callable[..., str | None],
) -> None:
    """Do not persist a digest when optional session context is absent."""
    assert hash_value(value=None, secret="s" * 32) is None

"""Tests for OAuth2 authorization-code helpers."""

import pytest
from app.oauth2.authorization.code import (
    create_s256_code_challenge,
    verify_s256_code_challenge,
)


pytestmark = pytest.mark.unit

AUTH_CODE_HASH_SECRET = "test-authorization-code-hash-secret-with-more-than-32-bytes"  # noqa: S105
CODE_VERIFIER = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"


def test_s256_pkce_verification() -> None:
    """Assert PKCE S256 challenge verification accepts only valid verifiers."""
    challenge = create_s256_code_challenge(code_verifier=CODE_VERIFIER)

    assert verify_s256_code_challenge(
        code_verifier=CODE_VERIFIER,
        code_challenge=challenge,
    )
    assert not verify_s256_code_challenge(
        code_verifier=f"{CODE_VERIFIER}x",
        code_challenge=challenge,
    )
    assert not verify_s256_code_challenge(
        code_verifier="too-short",
        code_challenge=challenge,
    )

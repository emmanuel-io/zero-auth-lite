"""Optional OpenID Connect constants and helpers."""

from app.oauth2.specs import OAuth2Specs


OPENID_SCOPE = "openid"
"""OIDC scope that requests identity semantics."""

OIDC_SUPPORTED_SCOPES = [OPENID_SCOPE, "email", "profile"]
"""OIDC scopes implemented by the optional OIDC layer."""

OIDC_USER_CLAIMS = [
    "sub",
    "email",
    "email_verified",
    "name",
    "given_name",
    "family_name",
]
"""Identity claims selected for ID tokens and UserInfo according to scopes."""

OIDC_ID_TOKEN_PROTOCOL_CLAIMS = [
    "iss",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
]
"""Protocol claims that this provider can include in an ID token."""

OIDC_SUPPORTED_CLAIMS = [*OIDC_ID_TOKEN_PROTOCOL_CLAIMS, *OIDC_USER_CLAIMS]
"""Claims that OIDC discovery advertises as supported by the provider."""

OIDC_SUBJECT_TYPES_SUPPORTED = ["public"]
"""Subject identifier types supported by this provider."""

OIDC_ID_TOKEN_SIGNING_ALGS_SUPPORTED = [OAuth2Specs.JWT_SIGNING_ALGORITHM]
"""ID token signing algorithms supported by this provider."""


def scope_includes_openid(scope: str) -> bool:
    """Return whether a space-separated scope string contains openid.

    Args:
        scope: Normalized space-separated OAuth2 scope string.

    Returns:
        bool: True when the OpenID Connect scope is present.
    """
    return OPENID_SCOPE in scope.split()

"""Optional OpenID Connect constants and helpers."""

from app.oauth2.specs import OAuth2Specs


# OIDC scope that requests identity semantics.
OPENID_SCOPE = "openid"

# Scopes implemented by the optional OIDC layer.
OIDC_SUPPORTED_SCOPES = [OPENID_SCOPE, "email", "profile"]

# Identity claims selected for ID tokens and UserInfo according to scopes.
OIDC_USER_CLAIMS = [
    "sub",
    "email",
    "email_verified",
    "name",
    "given_name",
    "family_name",
]

# Protocol claims that the provider can include in an ID token.
OIDC_ID_TOKEN_PROTOCOL_CLAIMS = [
    "iss",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
]

# Claims advertised as supported through OIDC discovery.
OIDC_SUPPORTED_CLAIMS = [*OIDC_ID_TOKEN_PROTOCOL_CLAIMS, *OIDC_USER_CLAIMS]

# Subject identifier types supported by this provider.
OIDC_SUBJECT_TYPES_SUPPORTED = ["public"]

# ID token signing algorithms supported by this provider.
OIDC_ID_TOKEN_SIGNING_ALGS_SUPPORTED = [OAuth2Specs.JWT_SIGNING_ALGORITHM]


def scope_includes_openid(scope: str) -> bool:
    """Return whether a normalized scope string contains ``openid``."""
    return OPENID_SCOPE in scope.split()

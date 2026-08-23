"""Validation constants for OAuth2 domain data."""

from typing import Final

from app.core.specs import SHA256_HEX_LENGTH


class OAuth2Specs:
    """Namespace for OAuth2 field limits and domain constants.

    Models, schemas, and DTOs share these protocol contracts.
    """

    JWT_SIGNING_ALGORITHM: Final[str] = "Ed25519"
    CLIENT_ID_LENGTH_MAX: Final[int] = 32
    CLIENT_SECRET_HASH_LENGTH_MAX: Final[int] = 128
    CLIENT_NAME_LENGTH_MAX: Final[int] = 100
    REDIRECT_URI_LENGTH_MAX: Final[int] = 256
    KEY_ID_LENGTH_MAX: Final[int] = 128
    HASH_LENGTH: Final[int] = SHA256_HEX_LENGTH
    TRANSACTION_TOKEN_BYTES: Final[int] = 32
    CLIENT_SECRET_BYTES: Final[int] = 32
    CLIENT_ID_RANDOM_BYTES: Final[int] = 18
    CLIENT_ORGANIZATION_ASSIGNMENTS_MAX: Final[int] = 100
    AUTHORIZATION_CODE_BYTES: Final[int] = 48
    DEVICE_CODE_BYTES: Final[int] = 48
    ACCESS_TOKEN_JTI_BYTES: Final[int] = 16
    REFRESH_TOKEN_BYTES: Final[int] = 64
    GRANT_TYPE_LENGTH_MAX: Final[int] = 64
    RESPONSE_TYPE_LENGTH_MAX: Final[int] = 32
    PROTOCOL_VALUE_LENGTH_MAX: Final[int] = 1024
    STATE_LENGTH_MAX: Final[int] = 512
    NONCE_LENGTH_MAX: Final[int] = 512
    CODE_VERIFIER_LENGTH_MIN: Final[int] = 43
    CODE_VERIFIER_LENGTH_MAX: Final[int] = 128
    CODE_VERIFIER_PATTERN: Final[str] = (
        rf"^[A-Za-z0-9._~-]{{{CODE_VERIFIER_LENGTH_MIN},{CODE_VERIFIER_LENGTH_MAX}}}$"
    )
    CODE_CHALLENGE_LENGTH_MIN: Final[int] = 43
    CODE_CHALLENGE_LENGTH_MAX: Final[int] = 43
    CODE_CHALLENGE_PATTERN: Final[str] = (
        rf"^[A-Za-z0-9_-]{{{CODE_CHALLENGE_LENGTH_MIN}}}$"
    )
    CODE_CHALLENGE_METHOD_LENGTH_MAX: Final[int] = 10
    SCOPE_NAME_LENGTH_MAX: Final[int] = 48
    SCOPE_LIST_LENGTH_MAX: Final[int] = 512

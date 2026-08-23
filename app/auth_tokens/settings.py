"""Settings for single-use auth workflow tokens."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, model_validator, SecretStr

from app.auth_tokens.specs import AuthTokenSpecs


DerivationKeyId = Annotated[
    str,
    Field(
        min_length=1,
        max_length=AuthTokenSpecs.DERIVATION_KEY_ID_LENGTH_MAX,
        pattern=r"^[A-Za-z0-9._-]+$",
        description="Stable identifier persisted with derived workflow tokens",
    ),
]
DerivationSecret = Annotated[
    SecretStr,
    Field(
        min_length=32,
        description="HMAC secret used to derive idempotent workflow tokens",
    ),
]
DEFAULT_AUTH_TOKEN_DERIVATION_SECRET = (
    "dev-auth-token-derivation-secret-for-local-server-example"  # noqa: S105
)


class PreviousDerivationSecretSettings(BaseModel):
    """Retained derivation secret used while workflow tokens remain valid."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key_id: DerivationKeyId
    secret: DerivationSecret


class AuthTokenSettings(BaseModel):
    """Lifetimes for single-use authentication token purposes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    derivation_key_id: DerivationKeyId = "default"
    derivation_secret: DerivationSecret = SecretStr(
        DEFAULT_AUTH_TOKEN_DERIVATION_SECRET
    )
    previous_derivation_secrets: tuple[PreviousDerivationSecretSettings, ...] = ()

    verify_token_ttl_seconds: Annotated[
        int, Field(ge=60, description="Token TTL for verification tokens")
    ] = 86_400  # 24 hours
    invite_token_ttl_seconds: Annotated[
        int, Field(ge=60, description="Token TTL for invite tokens")
    ] = 604_800  # 7 days
    reset_token_ttl_seconds: Annotated[
        int, Field(ge=60, description="Token TTL for password reset tokens")
    ] = 3_600  # 1 hour

    @model_validator(mode="after")
    def validate_derivation_keyring(self) -> "AuthTokenSettings":
        """Keep every derivation key identifier unique."""
        previous_key_ids = [item.key_id for item in self.previous_derivation_secrets]
        if len(previous_key_ids) != len(set(previous_key_ids)):
            msg = "Previous derivation key identifiers must be unique."
            raise ValueError(msg)
        if self.derivation_key_id in previous_key_ids:
            msg = "The active derivation_key_id cannot also be a previous key."
            raise ValueError(msg)
        return self

    def derivation_secret_for(self, key_id: str) -> SecretStr | None:
        """Resolve one persisted key identifier from the rotation keyring."""
        if key_id == self.derivation_key_id:
            return self.derivation_secret
        return next(
            (
                item.secret
                for item in self.previous_derivation_secrets
                if item.key_id == key_id
            ),
            None,
        )

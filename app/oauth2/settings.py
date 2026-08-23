"""OAuth2 and OpenID Connect settings with no configuration I/O."""

import base64
import binascii
from datetime import timedelta
from enum import StrEnum
from typing import Self
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
    SecretStr,
)

from app.oauth2.specs import OAuth2Specs
from app.settings.defaults import (
    DEV_OAUTH2_PRIVATE_KEY_B64,
    DEV_OAUTH2_PUBLIC_KEY_B64,
    LOCAL_AUTH_ORIGIN,
)


DEFAULT_AUTHORIZATION_CODE_HASH_SECRET = (
    "dev-auth-code-hash-secret-for-local-server-example"  # noqa: S105
)
DEFAULT_TOKEN_HASH_SECRET = "dev-oauth2-token-hash-secret-for-local-server-example"  # noqa: S105
DEFAULT_JWT_AUDIENCE = "zero-auth-lite-example-api"


class OAuth2GrantType(StrEnum):
    """Supported OAuth2 grant types."""

    authorization_code = "authorization_code"
    refresh_token = "refresh_token"  # noqa: S105
    client_credentials = "client_credentials"
    device_code = "urn:ietf:params:oauth:grant-type:device_code"


class OAuth2PreviousPublicKeySettings(BaseModel):
    """Previous public verification key exposed while rotation overlaps."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kid: str = Field(min_length=1, max_length=OAuth2Specs.KEY_ID_LENGTH_MAX)
    pub_key_b64: str


class OAuth2Settings(BaseModel):
    """OAuth2 and OpenID Connect settings; keys are loaded by providers."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_code_enabled: bool = True
    cleanup_interval_seconds: int = Field(default=3_600, ge=60)
    cleanup_batch_size: int = Field(default=100, ge=1, le=1_000)
    refresh_token_enabled: bool = True
    client_credentials_enabled: bool = True
    device_code_enabled: bool = True
    prv_key_b64: str | None = DEV_OAUTH2_PRIVATE_KEY_B64
    pub_key_b64: str | None = DEV_OAUTH2_PUBLIC_KEY_B64
    authorization_code_hash_secret: SecretStr = Field(
        default=SecretStr(DEFAULT_AUTHORIZATION_CODE_HASH_SECRET),
        min_length=32,
    )
    token_hash_secret: SecretStr = Field(
        default=SecretStr(DEFAULT_TOKEN_HASH_SECRET),
        min_length=32,
    )
    authorization_code_ttl_seconds: int = Field(default=300, gt=0)
    access_token_lifetime_seconds: int = Field(default=900, gt=0)
    id_token_lifetime_seconds: int = Field(default=900, gt=0)
    refresh_token_lifetime_seconds: int = Field(default=2_592_000, gt=0)
    device_code_lifetime_seconds: int = Field(default=1_800, gt=0)
    device_code_interval_seconds: int = Field(default=5, gt=0)
    device_code_create_attempts: int = Field(default=5, ge=1, le=20)
    allow_client_secret_post: bool = True
    jwt_issuer: str = LOCAL_AUTH_ORIGIN
    jwt_audience: str = DEFAULT_JWT_AUDIENCE
    jwt_key_id: str | None = "local-dev-key"
    jwks_enabled: bool = True
    oidc_enabled: bool = True
    previous_public_keys: tuple[OAuth2PreviousPublicKeySettings, ...] = ()

    @classmethod
    def disabled(cls) -> Self:
        """Return an explicit configuration with every protocol feature disabled."""
        return cls(
            authorization_code_enabled=False,
            refresh_token_enabled=False,
            client_credentials_enabled=False,
            device_code_enabled=False,
            prv_key_b64=None,
            pub_key_b64=None,
            jwt_key_id=None,
            jwks_enabled=False,
            oidc_enabled=False,
        )

    @model_validator(mode="after")
    def validate_oidc_grant_policy(self) -> "OAuth2Settings":
        """Ensure OIDC is not enabled without authorization-code support."""
        if self.oidc_enabled and not self.is_grant_enabled(
            OAuth2GrantType.authorization_code
        ):
            msg = "oidc_enabled requires authorization_code_enabled"
            raise ValueError(msg)
        try:
            AnyHttpUrl(self.jwt_issuer)
        except ValueError as exc:
            msg = "jwt_issuer must be an absolute HTTP(S) URL"
            raise ValueError(msg) from exc
        issuer = urlsplit(self.jwt_issuer)
        if issuer.scheme not in {"http", "https"} or issuer.hostname is None:
            msg = "jwt_issuer must be an absolute HTTP(S) URL with a hostname"
            raise ValueError(msg)
        if issuer.username is not None or issuer.password is not None:
            msg = "jwt_issuer must not contain user information"
            raise ValueError(msg)
        if issuer.query or issuer.fragment:
            msg = "jwt_issuer must not contain a query string or fragment"
            raise ValueError(msg)
        if self.oidc_enabled and not self.jwks_enabled:
            msg = "oidc_enabled requires jwks_enabled"
            raise ValueError(msg)
        if (self.oidc_enabled or self.jwks_enabled) and not self.jwt_key_id:
            msg = "OIDC and JWKS publication require jwt_key_id"
            raise ValueError(msg)
        previous_key_ids = [item.kid for item in self.previous_public_keys]
        all_key_ids = [self.jwt_key_id, *previous_key_ids]
        configured_key_ids = [item for item in all_key_ids if item is not None]
        if len(configured_key_ids) != len(set(configured_key_ids)):
            msg = "OAuth2 signing key identifiers must be unique"
            raise ValueError(msg)
        return self

    def is_grant_enabled(self, grant_type: OAuth2GrantType | str) -> bool:
        """Return whether an OAuth2 grant is globally enabled."""
        try:
            normalized = OAuth2GrantType(grant_type)
        except ValueError:
            return False
        explicit_grants = {
            OAuth2GrantType.authorization_code: self.authorization_code_enabled,
            OAuth2GrantType.refresh_token: self.refresh_token_enabled,
            OAuth2GrantType.client_credentials: self.client_credentials_enabled,
            OAuth2GrantType.device_code: self.device_code_enabled,
        }
        return explicit_grants[normalized]

    def enabled_grants(self) -> set[OAuth2GrantType]:
        """Return all globally enabled OAuth2 grants."""
        return {
            grant_type
            for grant_type in OAuth2GrantType
            if self.is_grant_enabled(grant_type)
        }

    @property
    def has_enabled_grants(self) -> bool:
        """Return whether at least one token grant is enabled."""
        return bool(self.enabled_grants())

    @property
    def protocol_enabled(self) -> bool:
        """Return whether any OAuth2 or OIDC protocol surface is enabled."""
        return self.has_enabled_grants or self.jwks_enabled

    def validate_startup_key_material(self) -> None:
        """Validate key material required by the enabled OAuth2 features.

        Section settings remain usable in isolated domain tests without key
        material. The root application settings call this method to reject an
        incomplete runnable-server configuration before accepting requests.

        Raises:
            ValueError: If required key material is missing, malformed, or
                contains a private/public key mismatch.
        """
        if not self.protocol_enabled:
            return

        signing_required = self.has_enabled_grants
        verification_required = signing_required or self.jwks_enabled
        if not verification_required:
            return
        if signing_required and self.prv_key_b64 is None:
            msg = "Enabled OAuth2 grants require prv_key_b64"
            raise ValueError(msg)
        if self.pub_key_b64 is None:
            msg = "Enabled OAuth2 token verification requires pub_key_b64"
            raise ValueError(msg)
        if self.jwt_key_id is None:
            msg = "Enabled OAuth2 token signing and verification require jwt_key_id"
            raise ValueError(msg)

        public_key = self._load_public_key(self.pub_key_b64, name="pub_key_b64")
        if self.prv_key_b64 is not None:
            private_key = self._load_private_key(self.prv_key_b64)
            derived_public_bytes = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            configured_public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            if derived_public_bytes != configured_public_bytes:
                msg = "OAuth2 prv_key_b64 and pub_key_b64 do not form a key pair"
                raise ValueError(msg)

        if self.previous_public_keys:
            for previous_key in self.previous_public_keys:
                self._load_public_key(
                    previous_key.pub_key_b64,
                    name=f"previous_public_keys[{previous_key.kid}]",
                )

    @staticmethod
    def _decode_key(value: str, *, name: str) -> bytes:
        """Decode one base64-encoded raw Ed25519 key."""
        try:
            return base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            msg = f"{name} must contain valid base64-encoded Ed25519 key material"
            raise ValueError(msg) from exc

    @classmethod
    def _load_private_key(cls, value: str) -> ed25519.Ed25519PrivateKey:
        """Load and validate the configured raw Ed25519 private key."""
        raw_key = cls._decode_key(value, name="prv_key_b64")
        try:
            return ed25519.Ed25519PrivateKey.from_private_bytes(raw_key)
        except ValueError as exc:
            msg = "prv_key_b64 must contain a raw 32-byte Ed25519 private key"
            raise ValueError(msg) from exc

    @classmethod
    def _load_public_key(
        cls,
        value: str,
        *,
        name: str,
    ) -> ed25519.Ed25519PublicKey:
        """Load and validate one configured raw Ed25519 public key."""
        raw_key = cls._decode_key(value, name=name)
        try:
            return ed25519.Ed25519PublicKey.from_public_bytes(raw_key)
        except ValueError as exc:
            msg = f"{name} must contain a raw 32-byte Ed25519 public key"
            raise ValueError(msg) from exc

    @property
    def authorization_code_ttl_delta(self) -> timedelta:
        """Return authorization code TTL as a timedelta.

        Returns:
            timedelta: Authorization code time-to-live.
        """
        return timedelta(seconds=self.authorization_code_ttl_seconds)

"""Shared local defaults for the canonical Zero Auth Lite server."""

LOCAL_AUTH_ORIGIN = "https://auth.zero-auth-lite.localhost:8443"
"""Public browser origin used by the local server."""

LOCAL_ORIGINS = (
    LOCAL_AUTH_ORIGIN,
    "https://api.zero-auth-lite.localhost:8443",
    "http://localhost:8000",
)
"""Browser origins used by the local HTTPS example stack."""

DEV_OAUTH2_PRIVATE_KEY_B64 = "8+EAUJiqpmlXFLuCF2v4LU6d8TKVp1R3JE3UwdrNhNI="
"""Development-only Ed25519 private key for repeatable local examples."""

DEV_OAUTH2_PUBLIC_KEY_B64 = "37TbbJO+trhWq5Wqva6QfrOsN5DwQjy5R1evwH2vutY="
"""Development-only Ed25519 public key for repeatable local examples."""

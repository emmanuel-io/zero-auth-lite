"""Deterministic UUIDv4 values for tests."""

from hashlib import sha256
from uuid import UUID


def deterministic_uuid(value: int | str | UUID) -> UUID:
    """Build a stable UUIDv4 from a compact test seed."""
    if isinstance(value, UUID):
        return value
    seed = str(value).encode()
    return UUID(bytes=sha256(seed).digest()[:16], version=4)


PublicId = deterministic_uuid
TEST_USER_CLIENT_ID = deterministic_uuid("test-user-client")
PUBLIC_CLIENT_ID = deterministic_uuid("public-client")
OIDC_CLIENT_ID = deterministic_uuid("oidc-client")
CONFIDENTIAL_CLIENT_ID = deterministic_uuid("confidential-client")
OTHER_PUBLIC_CLIENT_ID = deterministic_uuid("other-public-client")
MACHINE_CLIENT_ID = deterministic_uuid("machine-client")
PUBLIC_MACHINE_CLIENT_ID = deterministic_uuid("public-machine-client")
DEVICE_CLIENT_ID = deterministic_uuid("device-client")
UUID4_PATTERN = r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
UUID4_VERSION = 4


def format_public_id(value: UUID) -> str:
    """Serialize a public UUID in its canonical form."""
    return str(value)


def parse_public_id(value: str) -> UUID:
    """Parse a canonical UUID string for test assertions."""
    return UUID(value)

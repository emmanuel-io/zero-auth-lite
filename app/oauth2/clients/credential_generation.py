"""Generate OAuth2 client identifiers and secrets."""

from secrets import token_urlsafe
from uuid import UUID, uuid4

from app.oauth2.specs import OAuth2Specs


def generate_oauth2_client_id() -> UUID:
    """Return a random OAuth2 client UUID."""
    return uuid4()


def generate_oauth2_client_secret() -> str:
    """Return a URL-safe OAuth2 client secret."""
    return token_urlsafe(OAuth2Specs.CLIENT_SECRET_BYTES)

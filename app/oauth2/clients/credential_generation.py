"""Generate OAuth2 client identifiers and secrets."""

from secrets import token_urlsafe

from app.oauth2.specs import OAuth2Specs


def generate_oauth2_client_id() -> str:
    """Return a URL-safe OAuth2 client identifier."""
    return f"oa_{token_urlsafe(OAuth2Specs.CLIENT_ID_RANDOM_BYTES)}"


def generate_oauth2_client_secret() -> str:
    """Return a URL-safe OAuth2 client secret."""
    return token_urlsafe(OAuth2Specs.CLIENT_SECRET_BYTES)

"""Smallest supported browser-auth server without OAuth2 or OIDC."""

from app.main import create_app
from app.oauth2.settings import OAuth2Settings
from app.settings.root import Settings


settings = Settings(
    oauth2=OAuth2Settings.disabled(),
)
app = create_app(settings)

"""Smallest supported browser-auth server without OAuth2 or OIDC."""

from app.main import create_app
from app.oauth2.settings import OAuth2Settings
from app.settings.api import APISettings
from app.settings.root import Settings


settings = Settings(
    api=APISettings(interactive_auth_routes_enabled=False),
    oauth2=OAuth2Settings.disabled(),
)
app = create_app(settings)
